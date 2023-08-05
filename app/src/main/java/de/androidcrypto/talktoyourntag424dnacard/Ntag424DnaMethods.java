package de.androidcrypto.talktoyourntag424dnacard;

import static de.androidcrypto.talktoyourntag424dnacard.Utils.hexStringToByteArray;
import static de.androidcrypto.talktoyourntag424dnacard.Utils.intFrom3ByteArrayInversed;
import static de.androidcrypto.talktoyourntag424dnacard.Utils.intTo3ByteArrayInversed;
import static de.androidcrypto.talktoyourntag424dnacard.Utils.printData;

import android.app.Activity;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.text.TextUtils;
import android.util.Log;
import android.widget.TextView;

import androidx.annotation.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AccessControlException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class is taking all methods to work with NXP NTAG 424 DNA tag
 * The read and write communication is done using the
 * CommunicationAdapterNtag424Dna.class as reading or writing to files
 * 2 and 3 may need to get chunked (maximum frame size 128 byte including
 * encryption and/or MAC overhead
 */

/*
This is the complete command set per NTAG 424 DNA NT4H2421Gx.pdf datasheet
                                                                 Impl.
Instruction                       CLA INS Communication mode     Status

IsoSelectApplication               00  A4 CommMode.Plain         implemented
AuthenticateEV2First - Part1       90  71 N/A (command specific) implemented
AuthenticateEV2First - Part2       90  AF                        implemented
AuthenticateEV2NonFirst - Part1    90  77 N/A (command specific) implemented
AuthenticateEV2NonFirst - Part2    90  AF                        implemented
AuthenticateLRPFirst - Part1       90  71 N/A (command specific) n/a yet
AuthenticateLRPFirst - Part2       90  AF                        n/a yet
AuthenticateLRPNonFirst - Part1    90  77 N/A (command specific) n/a yet
AuthenticateLRPNonFirst - Part2    90  AF                        n/a yet
ChangeFileSettings                 90  5F CommMode.Full
ChangeKey                          90  C4 CommMode.Full
GetCardUID                         90  51 CommMode.Full
GetFileCounters                    90  F6 CommMode.Full
GetFileSettings                    90  F5 CommMode.Plain         implemented
GetFileSettings                    90  F5 CommMode.MAC
GetKeyVersion                      90  64 CommMode.MAC
GetVersion - Part1                 90  60 CommMode.Plain         implemented
GetVersion - Part2                 90  AF CommMode.Plain         implemented
GetVersion - Part3                 90  AF CommMode.Plain         implemented
GetVersion - Part1                 90  60 CommMode.MAC [1]
GetVersion - Part2                 90  AF CommMode.MAC [1]
GetVersion - Part3                 90  AF CommMode.MAC [1]
ISOReadBinary                      00  B0 CommMode.Plain
ReadData                           90  AD Comm. mode of targeted file
Read_Sig                           90  3C CommMode.Full
ISOSelectFile                      00  A4 CommMode.Plain
SetConfiguration                   90  5C CommMode.Full
ISOUpdateBinary                    00  D6 CommMode.Plain
WriteData                          90  8D Comm. mode of targeted file
 */

/*
A NTAG 424 DNA tag contains 3 pre defined Standard files (factory settings):
 File             Access Right keys
number | Length | RW | CAR | R | W | Communication mode
  01h  |    32  |  0 |  0  | E | 0 | CommMode.Plain
  02h  |   256  |  E |  E  | 0 | E | CommMode.Plain
  03h  |   128  |  3 |  0  | 2 | 3 | CommMode.Full
 */

public class Ntag424DnaMethods {

    private static final String TAG = Ntag424DnaMethods.class.getName();
    private static final boolean TEST_MODE = false;
    private Tag tag;
    private TextView textView; // used for displaying information's from the methods
    private Activity activity;
    // data from the tag on Init
    private IsoDep isoDep;
    private byte[] uid;
    private String[] techList;
    private boolean isIsoDepConnected = false;
    private VersionInfo versionInfo;
    private boolean isTagNtag424Dna = false;

    private boolean isApplicationSelected = false;
    private boolean printToLog = true; // print data to log
    private String logData;
    private byte[] errorCode = new byte[2];
    private String errorCodeReason;

    /**
     * variables are retrieved during authenticateEv2First and
     * cleared by invalidateAllData (and partially cleared by invalidateAllDataNonFirst)
     */
    private boolean authenticateEv2FirstSuccess = false;
    private boolean authenticateEv2NonFirstSuccess = false;
    private byte keyNumberUsedForAuthentication = -1;
    private byte[] SesAuthENCKey; // filled by authenticateAesEv2First
    private byte[] SesAuthMACKey; // filled by authenticateAesEv2First
    private int CmdCounter = 0; // filled / resetted by authenticateAesEv2First
    private byte[] TransactionIdentifier; // resetted by authenticateAesEv2First
    // note on TransactionIdentifier: LSB encoding

    /**
     * the CommunicationAdapter is initialized on initializing this class
     */

    CommunicationAdapterNtag424Dna communicationAdapter;

    /**
     * constants
     */

    private static final byte GET_VERSION_INFO_COMMAND = (byte) 0x60;
    private static final byte GET_KEY_VERSION_COMMAND = (byte) 0x64;
    private static final byte GET_ADDITIONAL_FRAME_COMMAND = (byte) 0xAF;
    private static final byte SELECT_APPLICATION_ISO_COMMAND = (byte) 0xA4;
    private static final byte GET_FILE_SETTINGS_COMMAND = (byte) 0xF5;
    private static final byte READ_STANDARD_FILE_COMMAND = (byte) 0xAD; // different to DESFire !
    private static final byte READ_STANDARD_FILE_SECURE_COMMAND = (byte) 0xAD;
    private static final byte WRITE_STANDARD_FILE_SECURE_COMMAND = (byte) 0x8D;
    private static final byte AUTHENTICATE_EV2_FIRST_COMMAND = (byte) 0x71;
    private static final byte AUTHENTICATE_EV2_NON_FIRST_COMMAND = (byte) 0x77;

    /**
     * NTAG 424 DNA specific constants
     */

    private final byte[] NTAG_424_DNA_DF_APPLICATION_NAME = Utils.hexStringToByteArray("D2760000850101");
    private static final byte STANDARD_FILE_NUMBER_01_CC = (byte) 0x01;
    private static final byte STANDARD_FILE_NUMBER_02 = (byte) 0x02;
    private static final byte STANDARD_FILE_NUMBER_03 = (byte) 0x03;

    // Status codes
    private static final byte OPERATION_OK = (byte) 0x00;
    private static final byte PERMISSION_DENIED = (byte) 0x9D;
    private static final byte AUTHENTICATION_ERROR = (byte) 0xAE;
    private static final byte ADDITIONAL_FRAME = (byte) 0xAF;
    // Response codes
    private static final byte[] RESPONSE_OK = new byte[]{(byte) 0x91, (byte) 0x00};
    private static final byte[] RESPONSE_ISO_OK = new byte[]{(byte) 0x90, (byte) 0x00};
    private static final byte[] RESPONSE_MORE_DATA_AVAILABLE = new byte[]{(byte) 0x91, (byte) 0xAF};
    private static final byte[] RESPONSE_LENGTH_ERROR = new byte[]{(byte) 0x91, (byte) 0x7E};
    private static final byte[] RESPONSE_FAILURE = new byte[]{(byte) 0x91, (byte) 0xFF}; // general, undefined failure


    private static final byte[] RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS = new byte[]{(byte) 0x91, (byte) 0xFD};
    private static final byte[] RESPONSE_FAILURE_MISSING_AUTHENTICATION = new byte[]{(byte) 0x91, (byte) 0xFE};
    private static final byte[] HEADER_ENC = new byte[]{(byte) (0x5A), (byte) (0xA5)}; // fixed to 0x5AA5
    private static final byte[] HEADER_MAC = new byte[]{(byte) (0xA5), (byte) (0x5A)}; // fixed to 0x5AA5

    private static final byte[] PADDING_FULL = hexStringToByteArray("80000000000000000000000000000000");


    public Ntag424DnaMethods(TextView textView, Tag tag, Activity activity) {
        this.tag = tag;
        this.textView = textView;
        this.activity = activity;
        Log.d(TAG, "Ntag424DnaMethods initializing");
        boolean success = initializeCard();
        if (success) {
            errorCode = RESPONSE_OK.clone();
        } else {
            errorCode = RESPONSE_FAILURE.clone();
        }
    }

    /**
     * get the version information of the discovered tag
     * @return the analyzed version information class
     *
     * see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 27-28
     */

    public VersionInfo getVersionInfo() {
        try {
            byte[] bytes = sendRequest(GET_VERSION_INFO_COMMAND);
            return new VersionInfo(bytes);
        } catch (IOException e) {
            errorCodeReason = "IOException: " + e.getMessage();
            Log.e(TAG, e.getMessage());
            e.printStackTrace();
            return null;
        } catch (Exception e) {
            errorCodeReason = "Exception: " + e.getMessage();
            Log.e(TAG, e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    public boolean selectNdefApplicationIso() {
        return selectNdefApplicationIso(NTAG_424_DNA_DF_APPLICATION_NAME);
    }

    /**
     * selects an application on the discovered tag by application name (ISO command)
     * @param dfApplicationName
     * @return
     *
     * Note: The NTAG 424 DNA has ONE pre defined application with name "D2760000850101"
     * see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 25-26
     */

    private boolean selectNdefApplicationIso(byte[] dfApplicationName) {
        String logData = "";
        final String methodName = "selectNdefApplicationIso";
        log(methodName, "started", true);
        log(methodName, printData("dfApplicationName", dfApplicationName));
        if (!isTagNtag424Dna) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "discovered tag is not a NTAG424DNA tag, aborted";
            return false;
        }
        if (isoDep == null) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "isoDep is NULL (maybe it is not a NTAG424DNA tag ?), aborted";
            return false;
        }
        if (dfApplicationName == null) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "dfApplicationName is NULL, aborted";
            return false;
        }
        // build command
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write((byte) 0x00);
        baos.write(SELECT_APPLICATION_ISO_COMMAND);
        baos.write((byte) 0x04); // select by DF name
        baos.write((byte) 0x0C);
        baos.write(dfApplicationName.length);
        baos.write(dfApplicationName, 0, dfApplicationName.length);
        baos.write((byte) 0x00); // le
        byte[] apdu = baos.toByteArray();
        byte[] response = sendData(apdu);
        if (checkResponseIso(response)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            isApplicationSelected = true;
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    public FileSettings[] getAllFileSettings() {
        // returns the fileSettings of all 3 pre installed files on NTAG 424 DNA
        FileSettings[] fileSettings = new FileSettings[3];
        /**
         * found a strange behaviour on the getFileSettings: after a (successful) authentication the first
         * getFileSettings command returns an 0x7e = 'length error', so in case of an error I'm trying to
         * get the file settings a second time
         */
        fileSettings[0] = new FileSettings(STANDARD_FILE_NUMBER_01_CC, getFileSettings(STANDARD_FILE_NUMBER_01_CC));
        if (Arrays.equals(errorCode, RESPONSE_LENGTH_ERROR)) {
            // this is the strange behaviour, get the fileSettings again
            fileSettings[0] = new FileSettings(STANDARD_FILE_NUMBER_01_CC, getFileSettings(STANDARD_FILE_NUMBER_01_CC));
        }
        fileSettings[1] = new FileSettings(STANDARD_FILE_NUMBER_02, getFileSettings(STANDARD_FILE_NUMBER_02));
        fileSettings[2] = new FileSettings(STANDARD_FILE_NUMBER_03, getFileSettings(STANDARD_FILE_NUMBER_03));
        return fileSettings;
    }

    /**
     * reads the fileSettings of a file and returns a byte array that length depends on settings on
     * Secure Dynamic Messaging (SDM) - if enabled the length is longer than 7 bytes (disabled SDM)
     * @param fileNumber
     * @return
     *
     * see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 26-27
     */
    private byte[] getFileSettings(byte fileNumber) {
        String logData = "";
        final String methodName = "getFileSettings";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + (int) fileNumber);
        if (!isTagNtag424Dna) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "discovered tag is not a NTAG424DNA tag, aborted";
            return null;
        }
        if (isoDep == null) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "isoDep is NULL (maybe it is not a NTAG424DNA tag ?), aborted";
            return null;
        }
        if ((fileNumber < (byte) 0x01) || (fileNumber > (byte) 0x03)) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "fileNumber not in range 1..3, aborted";
            return null;
        }
        byte[] apdu = new byte[0];
        byte[] response;
        try {
            apdu = wrapMessage(GET_FILE_SETTINGS_COMMAND, new byte[]{fileNumber});
            response = sendData(apdu);
        } catch (IOException e) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: " + e.getMessage();
            return null;
        }
        if (checkResponse(response)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            isApplicationSelected = true;
            return getData(response);
        } else {
            log(methodName, methodName + " FAILURE");
            byte[] responseBytes = returnStatusBytes(response);
            System.arraycopy(responseBytes, 0, errorCode, 0, 2);
            errorCodeReason = methodName + " FAILURE";
            return null;
        }
    }

    /**
     * authenticateAesEv2First uses the EV2First authentication method with command 0x71
     *
     * @param keyNo (00..14) but maximum is defined during application setup
     * @param key   (AES key with length of 16 bytes)
     * @return TRUE when authentication was successful
     * <p>
     * Note: the authentication seems to work but the correctness of the SesAuthENCKey and SesAuthMACKey is NOT tested so far
     * <p>
     * This method is using the AesCmac class for CMAC calculations
     */

    public boolean authenticateAesEv2First(byte keyNo, byte[] key) {

        /**
         * see MIFARE DESFire Light contactless application IC.pdf, pages 27 ff and 55ff
         * and NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf, pages 29-30
         *
         * Purpose: To start a new transaction
         * Capability Bytes: PCD and PICC capability bytes are exchanged (PDcap2, PCDcap2)
         * Transaction Identifier: A new transaction identifier is generated which remains valid for the full transaction
         * Command Counter: CmdCtr is reset to 0x0000
         * Session Keys: New session keys are generated
         */

        // see example in Mifare DESFire Light Features and Hints AN12343.pdf pages 33 ff
        // and MIFARE DESFire Light contactless application IC MF2DLHX0.pdf pages 52 ff

        logData = "";
        invalidateAllData();
        final String methodName = "authenticateAesEv2First";
        log(methodName, "keyNo: " + keyNo + printData(" key", key), true);
        errorCode = new byte[2];
        // sanity checks
        if (keyNo < 0) {
            Log.e(TAG, methodName + " keyNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if (keyNo > 14) {
            Log.e(TAG, methodName + " keyNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((key == null) || (key.length != 16)) {
            Log.e(TAG, methodName + " data length is not 16, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        log(methodName, "step 01 get encrypted rndB from card");
        log(methodName, "This method is using the AUTHENTICATE_AES_EV2_FIRST_COMMAND so it will work with AES-based application only");
        // authenticate 1st part
        byte[] apdu;
        byte[] response = new byte[0];
        try {
            /**
             * note: the parameter needs to be a 2 byte long value, the first one is the key number and the second
             * one could any LEN capability ??
             * I'm setting the byte[] to keyNo | 0x00
             */
            byte[] parameter = new byte[2];
            parameter[0] = keyNo;
            parameter[1] = (byte) 0x00; // is already 0x00
            log(methodName, printData("parameter", parameter));
            apdu = wrapMessage(AUTHENTICATE_EV2_FIRST_COMMAND, parameter);
            log(methodName, "get enc rndB " + printData("apdu", apdu));
            //response = isoDep.transceive(apdu);
            response = sendData(apdu);
            log(methodName, "get enc rndB " + printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "IOException: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        // we are expecting that the status code is 0xAF means more data need to get exchanged
        if (!checkResponseMoreData(responseBytes)) {
            log(methodName, "expected to get get 0xAF as error code but  found: " + printData("errorCode", responseBytes) + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        // now we know that we can work with the response, 16 bytes long
        // R-APDU (Part 1) (E(Kx, RndB)) || SW1 || SW2
        byte[] rndB_enc = getData(response);
        log(methodName, printData("encryptedRndB", rndB_enc));

        // start the decryption
        //byte[] iv0 = new byte[8];
        byte[] iv0 = new byte[16];
        log(methodName, "step 02 iv0 is 16 zero bytes " + printData("iv0", iv0));
        log(methodName, "step 03 decrypt the encryptedRndB using AES.decrypt with key " + printData("key", key) + printData(" iv0", iv0));
        byte[] rndB = AES.decrypt(iv0, key, rndB_enc);
        log(methodName, printData("rndB", rndB));

        log(methodName, "step 04 rotate rndB to LEFT");
        byte[] rndB_leftRotated = rotateLeft(rndB);
        log(methodName, printData("rndB_leftRotated", rndB_leftRotated));

        // authenticate 2nd part
        log(methodName, "step 05 generate a random rndA");
        byte[] rndA = new byte[16]; // this is an AES key
        rndA = getRandomData(rndA);
        log(methodName, printData("rndA", rndA));

        log(methodName, "step 06 concatenate rndA | rndB_leftRotated");
        byte[] rndArndB_leftRotated = concatenate(rndA, rndB_leftRotated);
        log(methodName, printData("rndArndB_leftRotated", rndArndB_leftRotated));

        // IV is now encrypted RndB received from the tag
        log(methodName, "step 07 iv1 is 16 zero bytes");
        byte[] iv1 = new byte[16];
        log(methodName, printData("iv1", iv1));

        // Encrypt RndAB_rot
        log(methodName, "step 08 encrypt rndArndB_leftRotated using AES.encrypt and iv1");
        byte[] rndArndB_leftRotated_enc = AES.encrypt(iv1, key, rndArndB_leftRotated);
        log(methodName, printData("rndArndB_leftRotated_enc", rndArndB_leftRotated_enc));

        // send encrypted data to PICC
        log(methodName, "step 09 send the encrypted data to the PICC");
        try {
            apdu = wrapMessage(GET_ADDITIONAL_FRAME_COMMAND, rndArndB_leftRotated_enc);
            log(methodName, "send rndArndB_leftRotated_enc " + printData("apdu", apdu));
            //response = isoDep.transceive(apdu);
            response = sendData(apdu);
            log(methodName, "send rndArndB_leftRotated_enc " + printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "IOException: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        // we are expecting that the status code is 0x00 means the exchange was OK
        if (!checkResponse(responseBytes)) {
            log(methodName, "expected to get get 0x00 as error code but  found: " + printData("errorCode", responseBytes) + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        // now we know that we can work with the response, response is 32 bytes long
        // R-APDU (Part 2) E(Kx, TI || RndA' || PDcap2 || PCDcap2) || Response Code
        log(methodName, "step 10 received encrypted data from PICC");
        byte[] data_enc = getData(response);
        log(methodName, printData("data_enc", data_enc));

        //IV is now reset to zero bytes
        log(methodName, "step 11 iv2 is 16 zero bytes");
        byte[] iv2 = new byte[16];
        log(methodName, printData("iv2", iv2));

        // Decrypt encrypted data
        log(methodName, "step 12 decrypt data_enc with iv2 and key");
        byte[] data = AES.decrypt(iv2, key, data_enc);
        log(methodName, printData("data", data));
        if (data == null) {
            Log.e(TAG, "data is NULL, aborted");
            log(methodName, "data is NULL, aborted");
            return false;
        }
        // data is 32 bytes long, e.g. a1487b61f69cef65a09742b481152325a7cb8fc6000000000000000000000000
        /**
         * structure of data
         * full example a1487b61f69cef65a09742b481152325a7cb8fc6000000000000000000000000
         *
         * TI transaction information 04 bytes a1487b61
         * rndA LEFT rotated          16 bytes f69cef65a09742b481152325a7cb8fc6
         * PDcap2                     06 bytes 000000000000
         * PCDcap2                    06 bytes 000000000000
         */

        // split data
        byte[] ti = new byte[4]; // LSB notation
        byte[] rndA_leftRotated = new byte[16];
        byte[] pDcap2 = new byte[6];
        byte[] pCDcap2 = new byte[6];
        System.arraycopy(data, 0, ti, 0, 4);
        System.arraycopy(data, 4, rndA_leftRotated, 0, 16);
        System.arraycopy(data, 20, pDcap2, 0, 6);
        System.arraycopy(data, 26, pCDcap2, 0, 6);
        log(methodName, "step 13 full data needs to get split up in 4 values");
        log(methodName, printData("data", data));
        log(methodName, printData("ti", ti));
        log(methodName, printData("rndA_leftRotated", rndA_leftRotated));
        log(methodName, printData("pDcap2", pDcap2));
        log(methodName, printData("pCDcap2", pCDcap2));

        // PCD compares send and received RndA
        log(methodName, "step 14 rotate rndA_leftRotated to RIGHT");
        byte[] rndA_received = rotateRight(rndA_leftRotated);
        log(methodName, printData("rndA_received ", rndA_received));
        boolean rndAEqual = Arrays.equals(rndA, rndA_received);
        //log(methodName, printData("rndA received ", rndA_received));
        log(methodName, printData("rndA          ", rndA));
        log(methodName, "rndA and rndA received are equal: " + rndAEqual);
        log(methodName, printData("rndB          ", rndB));

        log(methodName, "**** auth result ****");
        if (rndAEqual) {
            log(methodName, "*** AUTHENTICATED ***");
            SesAuthENCKey = getSesAuthEncKey(rndA, rndB, key);
            SesAuthMACKey = getSesAuthMacKey(rndA, rndB, key);
            log(methodName, printData("SesAuthENCKey ", SesAuthENCKey));
            log(methodName, printData("SesAuthMACKey ", SesAuthMACKey));
            CmdCounter = 0;
            TransactionIdentifier = ti.clone();
            authenticateEv2FirstSuccess = true;
            keyNumberUsedForAuthentication = keyNo;
        } else {
            log(methodName, "****   FAILURE   ****");
            invalidateAllData();
        }
        log(methodName, "*********************");
        return rndAEqual;
    }

    /**
     * authenticateAesEv2NonFirst uses the EV2NonFirst authentication method with command 0x77
     *
     * @param keyNo (00..14) but maximum is defined during application setup
     * @param key   (AES key with length of 16 bytes)
     * @return TRUE when authentication was successful
     * <p>
     * Note: the authentication seems to work but the correctness of the SesAuthENCKey and SesAuthMACKey is NOT tested so far
     * <p>
     * This method is using the AesCmac class for CMAC calculations
     */

    public boolean authenticateAesEv2NonFirst(byte keyNo, byte[] key) {
        /**
         * see MIFARE DESFire Light contactless application IC.pdf, pages 27 ff and 55 ff
         * The authentication consists of two parts: AuthenticateEV2NonFirst - Part1 and
         * AuthenticateEV2NonFirst - Part2. Detailed command definition can be found in
         * Section 11.4.2. This command is rejected if there is no active authentication, except if the
         * targeted key is the OriginalityKey. For the rest, the behavior is exactly the same as for
         * AuthenticateEV2First, except for the following differences:
         * • No PCDcap2 and PDcap2 are exchanged and validated.
         * • Transaction Identifier TI is not reset and not exchanged.
         * • Command Counter CmdCtr is not reset.
         * After successful authentication, the PICC remains in EV2 authenticated state. On any
         * failure during the protocol, the PICC ends up in not authenticated state.
         *
         * Purpose: To start a new session within the ongoing transaction
         * Capability Bytes: No capability bytes are exchanged
         * Transaction Identifier: No new transaction identifier is generated (old one remains and is reused)
         * Command Counter: CmdCounter stays active and continues counting from the current value
         * Session Keys: New session keys are generated
         */

        logData = "";
        invalidateAllDataNonFirst();
        final String methodName = "authenticateAesEv2NonFirst";
        log(methodName, printData("key", key) + " keyNo: " + keyNo, true);
        errorCode = new byte[2];
        // sanity checks
        if (!authenticateEv2FirstSuccess) {
            Log.e(TAG, methodName + " please run an authenticateEV2First before, aborted");
            log(methodName, "missing previous successfull authenticateEv2First, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if (keyNo < 0) {
            Log.e(TAG, methodName + " keyNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if (keyNo > 14) {
            Log.e(TAG, methodName + " keyNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((key == null) || (key.length != 16)) {
            Log.e(TAG, methodName + " data length is not 16, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        log(methodName, "step 01 get encrypted rndB from card");
        log(methodName, "This method is using the AUTHENTICATE_AES_EV2_NON_FIRST_COMMAND so it will work with AES-based application only");
        // authenticate 1st part
        byte[] apdu;
        byte[] response = new byte[0];
        try {
            /**
             * note: the parameter needs to be a 1 byte long value, the first one is the key number
             * I'm setting the byte[] to keyNo
             */
            byte[] parameter = new byte[1];
            parameter[0] = keyNo;
            log(methodName, printData("parameter", parameter));
            apdu = wrapMessage(AUTHENTICATE_EV2_NON_FIRST_COMMAND, parameter);
            log(methodName, "get enc rndB " + printData("apdu", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, "get enc rndB " + printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "IOException: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        // we are expecting that the status code is 0xAF means more data need to get exchanged
        if (!checkResponseMoreData(responseBytes)) {
            log(methodName, "expected to get get 0xAF as error code but  found: " + printData("errorCode", responseBytes) + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        // now we know that we can work with the response, 16 bytes long
        // R-APDU (Part 1) (E(Kx, RndB)) || SW1 || SW2
        byte[] rndB_enc = getData(response);
        log(methodName, printData("encryptedRndB", rndB_enc));

        // start the decryption
        //byte[] iv0 = new byte[8];
        byte[] iv0 = new byte[16];
        log(methodName, "step 02 iv0 is 16 zero bytes " + printData("iv0", iv0));
        log(methodName, "step 03 decrypt the encryptedRndB using AES.decrypt with key " + printData("key", key) + printData(" iv0", iv0));
        byte[] rndB = AES.decrypt(iv0, key, rndB_enc);
        log(methodName, printData("rndB", rndB));

        log(methodName, "step 04 rotate rndB to LEFT");
        byte[] rndB_leftRotated = rotateLeft(rndB);
        log(methodName, printData("rndB_leftRotated", rndB_leftRotated));

        // authenticate 2nd part
        log(methodName, "step 05 generate a random rndA");
        byte[] rndA = new byte[16]; // this is an AES key
        rndA = getRandomData(rndA);
        log(methodName, printData("rndA", rndA));

        log(methodName, "step 06 concatenate rndA | rndB_leftRotated");
        byte[] rndArndB_leftRotated = concatenate(rndA, rndB_leftRotated);
        log(methodName, printData("rndArndB_leftRotated", rndArndB_leftRotated));

        // IV is now encrypted RndB received from the tag
        log(methodName, "step 07 iv1 is 16 zero bytes");
        byte[] iv1 = new byte[16];
        log(methodName, printData("iv1", iv1));

        // Encrypt RndAB_rot
        log(methodName, "step 08 encrypt rndArndB_leftRotated using AES.encrypt and iv1");
        byte[] rndArndB_leftRotated_enc = AES.encrypt(iv1, key, rndArndB_leftRotated);
        log(methodName, printData("rndArndB_leftRotated_enc", rndArndB_leftRotated_enc));

        // send encrypted data to PICC
        log(methodName, "step 09 send the encrypted data to the PICC");
        try {
            apdu = wrapMessage(GET_ADDITIONAL_FRAME_COMMAND, rndArndB_leftRotated_enc);
            log(methodName, "send rndArndB_leftRotated_enc " + printData("apdu", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, "send rndArndB_leftRotated_enc " + printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "IOException: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        // we are expecting that the status code is 0x00 means the exchange was OK
        if (!checkResponse(responseBytes)) {
            log(methodName, "expected to get get 0x00 as error code but  found: " + printData("errorCode", responseBytes) + ", aborted");
            //System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        // now we know that we can work with the response, response is 16 bytes long
        // R-APDU (Part 2) E(Kx, RndA' || Response Code
        log(methodName, "step 10 received encrypted data from PICC");
        byte[] data_enc = getData(response);
        log(methodName, printData("data_enc", data_enc));

        //IV is now reset to zero bytes
        log(methodName, "step 11 iv2 is 16 zero bytes");
        byte[] iv2 = new byte[16];
        log(methodName, printData("iv2", iv2));

        // Decrypt encrypted data
        log(methodName, "step 12 decrypt data_enc with iv2 and key");
        byte[] data = AES.decrypt(iv2, key, data_enc);
        log(methodName, printData("data", data));
        // data is 32 bytes long, e.g. a1487b61f69cef65a09742b481152325a7cb8fc6000000000000000000000000
        /**
         * structure of data
         * full example 55c4421b4db67d0777c2f9116bcd6b1a
         *
         * rndA LEFT rotated          16 bytes 55c4421b4db67d0777c2f9116bcd6b1a
         */

        // split data not necessary, data is rndA_leftRotated
        byte[] rndA_leftRotated = data.clone();
        log(methodName, "step 13 full data is rndA_leftRotated only");
        log(methodName, printData("rndA_leftRotated", rndA_leftRotated));

        // PCD compares send and received RndA
        log(methodName, "step 14 rotate rndA_leftRotated to RIGHT");
        byte[] rndA_received = rotateRight(rndA_leftRotated);
        log(methodName, printData("rndA_received ", rndA_received));
        boolean rndAEqual = Arrays.equals(rndA, rndA_received);

        //log(methodName, printData("rndA received ", rndA_received));
        log(methodName, printData("rndA          ", rndA));
        log(methodName, "rndA and rndA received are equal: " + rndAEqual);
        log(methodName, printData("rndB          ", rndB));
        log(methodName, "**** auth result ****");
        if (rndAEqual) {
            log(methodName, "*** AUTHENTICATED ***");
            SesAuthENCKey = getSesAuthEncKey(rndA, rndB, key);
            SesAuthMACKey = getSesAuthMacKey(rndA, rndB, key);
            log(methodName, printData("SesAuthENCKey ", SesAuthENCKey));
            log(methodName, printData("SesAuthMACKey ", SesAuthMACKey));
            //CmdCounter = 0; // is not resetted in EV2NonFirst
            //TransactionIdentifier = ti.clone(); // is not resetted in EV2NonFirst
            authenticateEv2NonFirstSuccess = true;
            keyNumberUsedForAuthentication = keyNo;
        } else {
            log(methodName, "****   FAILURE   ****");
            invalidateAllData();
        }
        log(methodName, "*********************");
        return rndAEqual;
    }

    public List<byte[]> getReadAllFileContents() {
        List<byte[]> contentList = new ArrayList<>();
        //byte[] content = readStandardFileFull(STANDARD_FILE_NUMBER_01_CC, 0, 32);
        byte[] content = readStandardFilePlain(STANDARD_FILE_NUMBER_01_CC, 0, 32);
        contentList.add(content);

        //content  = readStandardFileFull(STANDARD_FILE_NUMBER_02, 0, 256);
        content  = readStandardFilePlain(STANDARD_FILE_NUMBER_02, 0, 256);
        contentList.add(content);
        content  = readStandardFileFull(STANDARD_FILE_NUMBER_03, 0, 0);
        //content  = readStandardFilePlain(STANDARD_FILE_NUMBER_03, 0, 128);
        contentList.add(content);
        return contentList;
    }

    public byte[] readStandardFilePlain(byte fileNumber, int offset, int length) {
        String logData = "";
        final String methodName = "readStandardFilePlain";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " offset: " + offset + " length: " + length);
        // sanity checks
        if ((fileNumber < 1) || (fileNumber > 3)) {
            log(methodName, "wrong fileNumber, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        if ((offset < 0) || (length < 1)) {
            log(methodName, "wrong offset or length, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        byte[] offsetBytes = Utils.intTo3ByteArrayInversed(offset);
        byte[] lengthBytes = Utils.intTo3ByteArrayInversed(length);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(offsetBytes, 0, offsetBytes.length);
        baos.write(lengthBytes, 0, lengthBytes.length);
        byte[] parameter = baos.toByteArray();
        byte[] apdu;
        byte[] response;
        try {
            apdu = wrapMessage(READ_STANDARD_FILE_COMMAND, parameter);
            log(methodName, printData("apdu", apdu));
            //response = communicationAdapter.sendReceiveChain(apdu);
            response = sendData(apdu);
            log(methodName, printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        byte[] responseBytes = returnStatusBytes(response);
                //byte[] responseBytes = communicationAdapter.getFullCode();
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        // the communicationAdapter.sendReceiveChain method return null on error
        /*
        if (response == null) {
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            log(methodName, "FAILURE with error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
         */
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return getData(response);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
    }

    public byte[] readStandardFileFull(byte fileNumber, int offset, int length) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 55 - 58
        // Cmd.ReadData in AES Secure Messaging using CommMode.Full
        // this is based on the read of a data file on a DESFire Light card

        // status

        String logData = "";
        final String methodName = "readStandardFileFull";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " offset: " + offset + " length: " + length);
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return null;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }

        byte[] offsetBytes = Utils.intTo3ByteArrayInversed(offset); // LSB order
        byte[] lengthBytes = Utils.intTo3ByteArrayInversed(length); // LSB order
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(offsetBytes, 0, 3);
        baosCmdHeader.write(lengthBytes, 0, 3);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));
        // example: 00000000300000
        // MAC_Input
        byte[] commandCounterLsb1 = Utils.intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(READ_STANDARD_FILE_SECURE_COMMAND); // 0xAD
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(cmdHeader, 0, cmdHeader.length);
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));
        // example: AD0100CD73D8E500000000300000
        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));
        // example: 7CF94F122B3DB05F

        // Constructing the full ReadData Command APDU
        ByteArrayOutputStream baosReadDataCommand = new ByteArrayOutputStream();
        baosReadDataCommand.write(cmdHeader, 0, cmdHeader.length);
        baosReadDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] readDataCommand = baosReadDataCommand.toByteArray();
        log(methodName, printData("readDataCommand", readDataCommand));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] fullEncryptedData;
        byte[] encryptedData;
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(READ_STANDARD_FILE_SECURE_COMMAND, readDataCommand);
            log(methodName, printData("apdu", apdu));
            //response = isoDep.transceive(apdu);
            response = sendData(apdu);
            log(methodName, printData("response", response));
            //Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
            fullEncryptedData = Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        // response length: 58 data: 8b61541d54f73901c8498c71dd45bae80578c4b1581aad439a806f37517c86ad4df8970279bbb8874ef279149aaa264c3e5eceb0e37a87699100

        // the fullEncryptedData is 56 bytes long, the first 48 bytes are encryptedData and the last 8 bytes are the responseMAC
        int encryptedDataLength = fullEncryptedData.length - 8;
        log(methodName, "The fullEncryptedData is of length " + fullEncryptedData.length + " that includedes 8 bytes for MAC");
        log(methodName, "The encryptedData length is " + encryptedDataLength);
        encryptedData = Arrays.copyOfRange(fullEncryptedData, 0, encryptedDataLength);
        responseMACTruncatedReceived = Arrays.copyOfRange(fullEncryptedData, encryptedDataLength, fullEncryptedData.length);
        log(methodName, printData("encryptedData", encryptedData));

        // start decrypting the data
        byte[] header = new byte[]{(byte) (0x5A), (byte) (0xA5)}; // fixed to 0x5AA5
        byte[] commandCounterLsb2 =
                Utils.intTo2ByteArrayInversed(CmdCounter);
        byte[] padding = hexStringToByteArray("0000000000000000");
        byte[] startingIv = new byte[16];
        ByteArrayOutputStream decryptBaos = new ByteArrayOutputStream();
        decryptBaos.write(header, 0, header.length);
        decryptBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        decryptBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        decryptBaos.write(padding, 0, padding.length);
        byte[] ivInputResponse = decryptBaos.toByteArray();
        log(methodName, printData("ivInputResponse", ivInputResponse));
        byte[] ivResponse = AES.encrypt(startingIv, SesAuthENCKey, ivInputResponse);
        log(methodName, printData("ivResponse", ivResponse));
        byte[] decryptedData = AES.decrypt(ivResponse, SesAuthENCKey, encryptedData);
        log(methodName, printData("decryptedData", decryptedData));
        byte[] readData = Arrays.copyOfRange(decryptedData, 0, length);
        log(methodName, printData("readData", readData));

        // verifying the received MAC
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        responseMacBaos.write(encryptedData, 0, encryptedData.length);
        byte[] macInput2 = responseMacBaos.toByteArray();
        log(methodName, printData("macInput", macInput2));
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput2);
        log(methodName, printData("responseMACTruncatedReceived  ", responseMACTruncatedReceived));
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMACTruncatedReceived)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return readData;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return null;
        }
    }



    public boolean writeStandardFileFull(byte fileNumber, byte[] dataToWrite, int offset, int length, boolean testMode) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 55 - 58
        // Cmd.WriteData in AES Secure Messaging using CommMode.Full
        // this is based on the write to a data file on a DESFire Light card

        // status WORKING - with prepared data blocks only:
        // todo add padding
        // if data length is a multiple of AES block length (16 bytes) we need to add a complete
        // block of padding data, beginning with 0x80 00 00...

        /**
         * Mifare DESFire Light Features and Hints AN12343.pdf page 30
         * 7.1.2 Encryption and Decryption
         * Encryption and decryption are done using the underlying block cipher (in this case
         * the AES block cipher) according to the CBC mode of the NIST Special Publication
         * 800-38A, see [6]. Padding is done according to Padding Method 2 (0x80 followed by zero
         * bytes) of ISO/IEC 9797-1. Note that if the original data is already a multiple of 16 bytes,
         * another additional padding block (16 bytes) is added. The only exception is during the
         * authentication itself, where no padding is applied at all.
         */

        String logData = "";
        final String methodName = "writeStandardFileEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, printData("dataToWrite", dataToWrite));
        // variables for testMode
        byte[] cmdData_expected = Utils.hexStringToByteArray("0102030405060708090A");
        byte fileNumber_expected = (byte) 0x03;
        int offset_expected = 0;
        int length_expected = 10;
        byte[] ivForCommandInput_expected = Utils.hexStringToByteArray("A55A7614281A00000000000000000000");
        byte[] ivForCommand_expected = Utils.hexStringToByteArray("4C651A64261A90307B6C293F611C7F7B");
        byte[] encryptedData_expected = Utils.hexStringToByteArray("6B5E6804909962FC4E3FF5522CF0F843");
        byte[] macInput_expected = Utils.hexStringToByteArray("8D00007614281A030000000A00006B5E6804909962FC4E3FF5522CF0F843");
        byte[] cmdHeader_expected = Utils.hexStringToByteArray("030000000A0000");
        byte[] mac_expected = Utils.hexStringToByteArray("426CD70CE153ED315E5B139CB97384AA");
        byte[] macTruncated_expected = Utils.hexStringToByteArray("6C0C53315B9C73AA");
        byte[] apdu_expected = Utils.hexStringToByteArray("908D00001F030000000A00006B5E6804909962FC4E3FF5522CF0F8436C0C53315B9C73AA00");
        byte[] response_expected = Utils.hexStringToByteArray("C26D236E4A7C046D9100");
        byte[] responseMacInput_expected = Utils.hexStringToByteArray("0001007614281A");
        byte[] responseMac_expected = Utils.hexStringToByteArray("86C2486D35237F6E974A437C4004C46D");
        byte[] responseMacTruncated_expected = Utils.hexStringToByteArray("FC222E5F7A542452");
        if (testMode) {
            log(methodName, "### This method is in TEST MODE, no transmission is performed ###");
            log(methodName, "using fixed values for TI etc");
            SesAuthMACKey = Utils.hexStringToByteArray("FC4AF159B62E549B5812394CAB1918CC");
            SesAuthENCKey = Utils.hexStringToByteArray("7A93D6571E4B180FCA6AC90C9A7488D4");
            CmdCounter = 0;
            TransactionIdentifier = Utils.hexStringToByteArray("7614281A");
            dataToWrite = Utils.hexStringToByteArray("0102030405060708090A");
        }
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // todo other sanity checks on values

        // step 8
        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        // MAC_Input
        byte[] commandCounterLsb1 = Utils.intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        //byte[] header = new byte[]{(byte) (0xA5), (byte) (0x5A)}; // fixed to 0xA55A
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(HEADER_MAC, 0, HEADER_MAC.length);
        baosIvInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosIvInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosIvInput.write(padding1, 0, padding1.length);
        byte[] ivForCommandInput = baosIvInput.toByteArray();
        log(methodName, printData("ivForCommandInput", ivForCommandInput));
        if (testMode) {
            boolean testResult = compareTestModeValues(ivForCommandInput, ivForCommandInput_expected, "ivInput");
            ivForCommandInput = ivForCommand_expected.clone();
        }

        // step 8 b encrypt to get ivForCommand
        // IV for CmdData = Enc(KSesAuthENC, IV_Input)
        log(methodName, printData("SesAuthENCKey", SesAuthENCKey));
        byte[] startingIv = new byte[16];
        byte[] ivForCmdData = AES.encrypt(startingIv, SesAuthENCKey, ivForCommandInput);
        log(methodName, printData("ivForCmdData", ivForCmdData));

        if (testMode) {
            boolean testResult = compareTestModeValues(ivForCmdData, ivForCommand_expected, "ivForCommand");
            ivForCmdData = ivForCommand_expected.clone();
        }

        // todo work on data that is longer than block length
        byte[] cmdData = dataToWrite.clone();
        if (testMode) {
            cmdData = cmdData_expected.clone();
        }

        // step 10 encrypt cmdData after padding
        // next step is to pad the data according to padding rules in desfire EV2/3 for AES Secure Messaging fullMode
        byte[] dataPadded = paddingWriteData(cmdData);
        log(methodName, printData("cmdData ", cmdData));
        log(methodName, printData("data pad", dataPadded));
        byte[] encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, dataPadded);
        log(methodName, printData("encryptedData", encryptedData));
        // step 11
        if (testMode) {
            boolean testResult = compareTestModeValues(encryptedData, encryptedData_expected, "encryptedData");
            ivForCommandInput = ivForCommand_expected.clone();
        }

        // step 12 CMD_HEADER (FileNumber || offset || length)
        if (testMode) {
            fileNumber = fileNumber_expected;
            offset = offset_expected;
            length = length_expected;
        }
        byte[] offsetBytes = intTo3ByteArrayInversed(offset);
        byte[] lengthBytes = intTo3ByteArrayInversed(length);
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(offsetBytes, 0, offsetBytes.length);
        baosCmdHeader.write(lengthBytes, 0, lengthBytes.length);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        if (testMode) {
            boolean testResult = compareTestModeValues(cmdHeader, cmdHeader_expected, "cmdHeader");
            cmdHeader = cmdHeader_expected.clone();
        }

        // step 12
        // MAC_Input (Ins || CmdCounter || TI || CmdHeader || Encrypted CmdData )
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(WRITE_STANDARD_FILE_SECURE_COMMAND); // 0x8D
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(cmdHeader, 0, cmdHeader.length);
        baosMacInput.write(encryptedData, 0, encryptedData.length);
        byte[] sendMacInput = baosMacInput.toByteArray();
        log(methodName, printData("sendMacInput", sendMacInput));

        if (testMode) {
            boolean testResult = compareTestModeValues(sendMacInput, macInput_expected, "sendMacInput");
            sendMacInput = macInput_expected.clone();
        }

        // step 13 encrypt macInput



        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, sendMacInput);
        log(methodName, printData("macFull", macFull));

        if (testMode) {
            boolean testResult = compareTestModeValues(macFull, mac_expected, "macFull");
            macFull = mac_expected.clone();
        }

        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        if (testMode) {
            boolean testResult = compareTestModeValues(macTruncated, macTruncated_expected, "macTruncated");
            macTruncated = macTruncated_expected.clone();
        }

        // error in Features and Hints, page 57, point 28:
        // Data (FileNo || Offset || DataLenght || Data) is NOT correct, as well not the Data Message
        // correct is the following concatenation:

        // Data (CmdHeader || Encrypted Data || MAC)
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        baosWriteDataCommand.write(cmdHeader, 0, cmdHeader.length);
        baosWriteDataCommand.write(encryptedData, 0, encryptedData.length);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] writeDataCommand = baosWriteDataCommand.toByteArray();
        log(methodName, printData("writeDataCommand", writeDataCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(WRITE_STANDARD_FILE_SECURE_COMMAND, writeDataCommand);
            log(methodName, printData("apdu", apdu));
            if (testMode) {
                boolean testResult = compareTestModeValues(apdu, apdu_expected, "apdu");
                response = response_expected.clone();
            } else {
                response = isoDep.transceive(apdu);
            }
            log(methodName, printData("response", response));
            //Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        byte[] commandCounterLsb2 = Utils.intTo2ByteArrayInversed(CmdCounter);

        // verifying the received Response MAC
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        byte[] macInput2 = responseMacBaos.toByteArray();
        log(methodName, printData("macInput2", macInput2));
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput2);
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        log(methodName, printData("responseMACTruncatedReceived  ", responseMACTruncatedReceived));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMACTruncatedReceived)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return false;
        }
    }

    /**
     * add the padding bytes to data that is written to a Standard, Backup, Linear Record or Cyclic Record file
     * The encryption method does need a byte array of multiples of 16 bytes
     * If the unpaddedData is of (multiple) length of 16 the complete padding is added
     * @param unpaddedData
     * @return the padded data
     */
    public byte[] paddingWriteData(byte[] unpaddedData) {
        // sanity checks
        if (unpaddedData == null) {
            Log.e(TAG, "paddingWriteData - unpaddedData is NULL, aborted");
            return null;
        }
        int unpaddedDataLength = unpaddedData.length;
        int paddingBytesLength = PADDING_FULL.length;
        byte[] fullPaddedData = new byte[unpaddedDataLength + paddingBytesLength];
        // concatenate unpaddedData and PADDING_FULL
        System.arraycopy(unpaddedData, 0, fullPaddedData, 0, unpaddedDataLength);
        System.arraycopy(PADDING_FULL, 0, fullPaddedData, unpaddedDataLength, paddingBytesLength);
        // this is maybe too long, trunc to multiple of 16 bytes
        int mult16 = fullPaddedData.length / 16;
        Log.d(TAG, "fullPaddedData.length: " + fullPaddedData.length);
        Log.d(TAG, "mult16               : " + mult16);
        return Arrays.copyOfRange(fullPaddedData, 0, (mult16 * 16));
    }

    private boolean compareTestModeValues(byte[] real, byte[] expected, String valueName) {
        if (Arrays.equals(real, expected)) {
            Log.d(TAG, "valueName: " + valueName + " EQUALS");
            return true;
        } else {
            Log.d(TAG, "valueName: " + valueName + " NOT EQUALS");
            Log.d(TAG, printData(valueName + " R", real));
            Log.d(TAG, printData(valueName + " E", expected));
            return false;
        }
    }

    public List<Byte> getAllKeyVersions() {
        List<Byte> byteList = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            byte keyVersion = getKeyVersion((byte) (i & 0x0f));
            byteList.add(keyVersion);
        }
        return byteList;
    }


    public byte getKeyVersion(byte keyNumber) {
        final String methodName = "getKeyVersion";
        log(methodName, "keyNumber: " + keyNumber, true);
        errorCode = new byte[2];
        // sanity checks
        if (keyNumber < 0) {
            Log.e(TAG, methodName + " keyNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return -1;
        }
        if (keyNumber > 14) {
            Log.e(TAG, methodName + " keyNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return -1;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return -1;
        }
        byte[] apdu;
        byte[] response;
        try {
            apdu = wrapMessage(GET_KEY_VERSION_COMMAND, new byte[]{keyNumber});
            response = sendData(apdu);
        } catch (Exception e) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "Exception: " + e.getMessage();
            Log.e(TAG, e.getMessage());
            e.printStackTrace();
            return -1;
        }
        if (checkResponse(response)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            isApplicationSelected = true;
            return getData(response)[0];
        } else {
            log(methodName, methodName + " FAILURE");
            byte[] responseBytes = returnStatusBytes(response);
            System.arraycopy(responseBytes, 0, errorCode, 0, 2);
            errorCodeReason = methodName + " FAILURE";
            return -1;
        }


    }


    /**
     * service methods
     */

    private boolean initializeCard() {
        String methodName = "initializeCard";
        if (tag == null) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "tag is NULL, aborted";
            return false;
        }
        uid = tag.getId();
        Log.d(TAG, printData("uid", uid));
        writeToUiAppend(textView, printData("UID", uid));
        techList = tag.getTechList();
        Log.d(TAG, "techList: " + Arrays.toString(techList));

        try {
            isoDep = IsoDep.get(tag);
            if (isoDep == null) {
                errorCode = RESPONSE_FAILURE.clone();
                errorCodeReason = "isoDep is NULL (maybe it is not a NTAG424DNA tag ?), aborted";
                return false;
            }
            Log.d(TAG, "tag is connected: " + isoDep.isConnected());
            isoDep.connect();
            Log.d(TAG, "tag is connected: " + isoDep.isConnected());
            if (isoDep.isConnected()) {
                isIsoDepConnected = true;
                Log.d(TAG, "tag is connected to isoDep");
            } else {
                Log.d(TAG, "could not connect to isoDep, aborted");
                isIsoDepConnected = false;
                errorCode = RESPONSE_FAILURE.clone();
                errorCodeReason = "could not connect to isoDep, aborted";
                isoDep.close();
                return false;
            }
            // initialize the Communication Adapter
            communicationAdapter = new CommunicationAdapterNtag424Dna(isoDep, printToLog);
            // get the version information
            versionInfo = getVersionInfo();
            if (versionInfo == null) {
                errorCode = RESPONSE_FAILURE.clone();
                errorCodeReason = "could not retrieve VersionInfo (maybe it is not a NTAG424DNA tag ?), aborted";
                return false;
            }
            if (versionInfo.getHardwareType() == (byte) 0x04) {
                isTagNtag424Dna = true;
                Log.d(TAG, "tag is identified as NTAG424DNA");
                log(methodName, versionInfo.dump());
                errorCode = RESPONSE_OK.clone();
                errorCodeReason = "SUCCESS";
                writeToUiAppend(textView, versionInfo.dump());
                Utils.vibrateShort(activity.getBaseContext());
                return true;
            } else {
                isTagNtag424Dna = false;
                Log.d(TAG, "tag is NOT identified as NTAG424DNA, aborted");
                writeToUiAppend(textView, "tag is NOT identified as NTAG424DNA, aborted");
                log(methodName, versionInfo.dump());
                errorCode = RESPONSE_FAILURE.clone();
                errorCodeReason = "could not retrieve VersionInfo (maybe it is not a NTAG424DNA tag ?), aborted";
                writeToUiAppend(textView, versionInfo.dump());
                return false;
            }
        } catch (IOException e) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: " + e.getMessage();
            Log.e(TAG, e.getMessage());
            e.printStackTrace();
            return false;
        } catch (Exception e) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "Exception: " + e.getMessage();
            Log.e(TAG, e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    // rotate the array one byte to the left
    private byte[] rotateLeft(byte[] data) {
        log("rotateLeft", printData("data", data), true);
        byte[] ret = new byte[data.length];
        System.arraycopy(data, 1, ret, 0, data.length - 1);
        ret[data.length - 1] = data[0];
        return ret;
    }

    // rotate the array one byte to the right
    private byte[] rotateRight(byte[] data) {
        log("rotateRight", printData("data", data), true);
        byte[] unrotated = new byte[data.length];
        for (int i = 1; i < data.length; i++) {
            unrotated[i] = data[i - 1];
        }
        unrotated[0] = data[data.length - 1];
        return unrotated;
    }

    private static byte[] concatenate(byte[] dataA, byte[] dataB) {
        byte[] concatenated = new byte[dataA.length + dataB.length];
        for (int i = 0; i < dataA.length; i++) {
            concatenated[i] = dataA[i];
        }

        for (int i = 0; i < dataB.length; i++) {
            concatenated[dataA.length + i] = dataB[i];
        }
        return concatenated;
    }

    /**
     * generates a random byte array with equals length of key
     * @param key
     * @return
     */

    private byte[] getRandomData(byte[] key) {
        log("getRandomData", printData("key", key), true);
        //Log.d(TAG, "getRandomData " + printData("var", var));
        int keyLength = key.length;
        return getRandomData(keyLength);
    }

    /**
     * generates a random byte array of 'length' length
     *
     * @return a byte[]
     */
    private byte[] getRandomData(int length) {
        log("getRandomData", "length: " + length, true);
        //Log.d(TAG, "getRandomData " + " length: " + length);
        byte[] value = new byte[length];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(value);
        return value;
    }

    /**
     * calculate the SessionAuthEncryptionKey after a successful authenticateAesEv2First
     * It uses the AesMac class for CMAC
     * The code is tested with example values in Mifare DESFire Light Features and Hints AN12343.pdf
     * on pages 33..35
     *
     * @param rndA              is the random generated 16 bytes long key A from reader
     * @param rndB              is the random generated 16 bytes long key B from PICC
     * @param authenticationKey is the 16 bytes long AES key used for authentication
     * @return the 16 bytes long (AES) encryption key
     */

    public byte[] getSesAuthEncKey(byte[] rndA, byte[] rndB, byte[] authenticationKey) {
        // see
        // see MIFARE DESFire Light contactless application IC pdf, page 28
        final String methodName = "getSesAuthEncKey";
        log(methodName, printData("rndA", rndA) + printData(" rndB", rndB) + printData(" authenticationKey", authenticationKey), false);
        // sanity checks
        if ((rndA == null) || (rndA.length != 16)) {
            log(methodName, "rndA is NULL or wrong length, aborted", false);
            return null;
        }
        if ((rndB == null) || (rndB.length != 16)) {
            log(methodName, "rndB is NULL or wrong length, aborted", false);
            return null;
        }
        if ((authenticationKey == null) || (authenticationKey.length != 16)) {
            log(methodName, "authenticationKey is NULL or wrong length, aborted", false);
            return null;
        }

        if (TEST_MODE) {
            writeToUiAppend(textView, "### TEST_MODE enabled ###");
            writeToUiAppend(textView, "using pre defined values");
            rndA = Utils.hexStringToByteArray("B98F4C50CF1C2E084FD150E33992B048");
            rndB = Utils.hexStringToByteArray("91517975190DCEA6104948EFA3085C1B");
            authenticationKey = Utils.hexStringToByteArray("00000000000000000000000000000000");
        }
        byte[] sv1_expected = Utils.hexStringToByteArray("A55A00010080B98FDD01B6693705CEA6104948EFA3085C1B4FD150E33992B048");
        byte[] sv2_expected = Utils.hexStringToByteArray("5AA500010080B98FDD01B6693705CEA6104948EFA3085C1B4FD150E33992B048");
        // named: Encryption Session Key
        byte[] SesAuthENCKey_expected = Utils.hexStringToByteArray("7A93D6571E4B180FCA6AC90C9A7488D4");
        // named CMAC Session Key
        byte[] SesAuthMACKey_expected = Utils.hexStringToByteArray("FC4AF159B62E549B5812394CAB1918CC");

/*
SV 1 = [0xA5][0x5A][0x00][0x01] [0x00][0x80][RndA[15:14] || [ (RndA[13:8] ⊕ RndB[15:10]) ] || [RndB[9:0] || RndA[7:0]
SV 2 = [0x5A][0xA5][0x00][0x01] [0x00][0x80][RndA[15:14] || [ (RndA[13:8] ⊕ RndB[15:10]) ] || [RndB[9:0] || RndA[7:0]
 */


        // see Mifare DESFire Light Features and Hints AN12343.pdf page 35
        byte[] cmacInput = new byte[32];
        byte[] labelEnc = new byte[]{(byte) (0xA5), (byte) (0x5A)}; // fixed to 0xA55A
        byte[] counter = new byte[]{(byte) (0x00), (byte) (0x01)}; // fixed to 0x0001
        byte[] length = new byte[]{(byte) (0x00), (byte) (0x80)}; // fixed to 0x0080

        System.arraycopy(labelEnc, 0, cmacInput, 0, 2);
        System.arraycopy(counter, 0, cmacInput, 2, 2);
        System.arraycopy(length, 0, cmacInput, 4, 2);
        System.arraycopy(rndA, 0, cmacInput, 6, 2);

        byte[] rndA02to07 = new byte[6];
        byte[] rndB00to05 = new byte[6];
        rndA02to07 = Arrays.copyOfRange(rndA, 2, 8);
        log(methodName, printData("rndA     ", rndA), false);
        log(methodName, printData("rndA02to07", rndA02to07), false);
        rndB00to05 = Arrays.copyOfRange(rndB, 0, 6);
        log(methodName, printData("rndB     ", rndB), false);
        log(methodName, printData("rndB00to05", rndB00to05), false);
        byte[] xored = xor(rndA02to07, rndB00to05);
        log(methodName, printData("xored     ", xored), false);
        System.arraycopy(xored, 0, cmacInput, 8, 6);
        System.arraycopy(rndB, 6, cmacInput, 14, 10);
        System.arraycopy(rndA, 8, cmacInput, 24, 8);

        log(methodName, printData("rndA     ", rndA), false);
        log(methodName, printData("rndB     ", rndB), false);
        log(methodName, printData("cmacInput", cmacInput), false);
        if (TEST_MODE) {
            boolean testResult = compareTestModeValues(cmacInput, sv1_expected, "SV1");
        }
        byte[] iv = new byte[16];
        log(methodName, printData("iv       ", iv), false);
        byte[] cmac = calculateDiverseKey(authenticationKey, cmacInput);
        log(methodName, printData("cmacOut ", cmac), false);
        if (TEST_MODE) {
            boolean testResult = compareTestModeValues(cmac, SesAuthENCKey_expected, "SesAUthENCKey");
        }
        return cmac;
    }

    public byte[] getSesAuthEncKeyDesfire(byte[] rndA, byte[] rndB, byte[] authenticationKey) {
        // see
        // see MIFARE DESFire Light contactless application IC pdf, page 28
        final String methodName = "getSesAuthEncKey";
        log(methodName, printData("rndA", rndA) + printData(" rndB", rndB) + printData(" authenticationKey", authenticationKey), false);
        // sanity checks
        if ((rndA == null) || (rndA.length != 16)) {
            log(methodName, "rndA is NULL or wrong length, aborted", false);
            return null;
        }
        if ((rndB == null) || (rndB.length != 16)) {
            log(methodName, "rndB is NULL or wrong length, aborted", false);
            return null;
        }
        if ((authenticationKey == null) || (authenticationKey.length != 16)) {
            log(methodName, "authenticationKey is NULL or wrong length, aborted", false);
            return null;
        }

        // see Mifare DESFire Light Features and Hints AN12343.pdf page 35
        byte[] cmacInput = new byte[32];
        byte[] labelEnc = new byte[]{(byte) (0xA5), (byte) (0x5A)}; // fixed to 0xA55A
        byte[] counter = new byte[]{(byte) (0x00), (byte) (0x01)}; // fixed to 0x0001
        byte[] length = new byte[]{(byte) (0x00), (byte) (0x80)}; // fixed to 0x0080

        System.arraycopy(labelEnc, 0, cmacInput, 0, 2);
        System.arraycopy(counter, 0, cmacInput, 2, 2);
        System.arraycopy(length, 0, cmacInput, 4, 2);
        System.arraycopy(rndA, 0, cmacInput, 6, 2);

        byte[] rndA02to07 = new byte[6];
        byte[] rndB00to05 = new byte[6];
        rndA02to07 = Arrays.copyOfRange(rndA, 2, 8);
        log(methodName, printData("rndA     ", rndA), false);
        log(methodName, printData("rndA02to07", rndA02to07), false);
        rndB00to05 = Arrays.copyOfRange(rndB, 0, 6);
        log(methodName, printData("rndB     ", rndB), false);
        log(methodName, printData("rndB00to05", rndB00to05), false);
        byte[] xored = xor(rndA02to07, rndB00to05);
        log(methodName, printData("xored     ", xored), false);
        System.arraycopy(xored, 0, cmacInput, 8, 6);
        System.arraycopy(rndB, 6, cmacInput, 14, 10);
        System.arraycopy(rndA, 8, cmacInput, 24, 8);

        log(methodName, printData("rndA     ", rndA), false);
        log(methodName, printData("rndB     ", rndB), false);
        log(methodName, printData("cmacInput", cmacInput), false);
        byte[] iv = new byte[16];
        log(methodName, printData("iv       ", iv), false);
        byte[] cmac = calculateDiverseKey(authenticationKey, cmacInput);
        log(methodName, printData("cmacOut ", cmac), false);
        return cmac;
    }

    /**
     * calculate the SessionAuthMacKey after a successful authenticateAesEv2First
     * It uses the AesMac class for CMAC
     * The code is tested with example values in Mifare DESFire Light Features and Hints AN12343.pdf
     * on pages 33..35
     *
     * @param rndA              is the random generated 16 bytes long key A from reader
     * @param rndB              is the random generated 16 bytes long key B from PICC
     * @param authenticationKey is the 16 bytes long AES key used for authentication
     * @return the 16 bytes long MAC key
     */

    public byte[] getSesAuthMacKey(byte[] rndA, byte[] rndB, byte[] authenticationKey) {
        // see
        // see MIFARE DESFire Light contactless application IC pdf, page 28
        final String methodName = "getSesAuthMacKey";
        log(methodName, printData("rndA", rndA) + printData(" rndB", rndB) + printData(" authenticationKey", authenticationKey), false);
        // sanity checks
        if ((rndA == null) || (rndA.length != 16)) {
            log(methodName, "rndA is NULL or wrong length, aborted", false);
            return null;
        }
        if ((rndB == null) || (rndB.length != 16)) {
            log(methodName, "rndB is NULL or wrong length, aborted", false);
            return null;
        }
        if ((authenticationKey == null) || (authenticationKey.length != 16)) {
            log(methodName, "authenticationKey is NULL or wrong length, aborted", false);
            return null;
        }
        // see Mifare DESFire Light Features and Hints AN12343.pdf page 35
        byte[] cmacInput = new byte[32];
        byte[] labelEnc = new byte[]{(byte) (0x5A), (byte) (0xA5)}; // fixed to 0x5AA5
        byte[] counter = new byte[]{(byte) (0x00), (byte) (0x01)}; // fixed to 0x0001
        byte[] length = new byte[]{(byte) (0x00), (byte) (0x80)}; // fixed to 0x0080

        System.arraycopy(labelEnc, 0, cmacInput, 0, 2);
        System.arraycopy(counter, 0, cmacInput, 2, 2);
        System.arraycopy(length, 0, cmacInput, 4, 2);
        System.arraycopy(rndA, 0, cmacInput, 6, 2);

        byte[] rndA02to07 = new byte[6];
        byte[] rndB00to05 = new byte[6];
        rndA02to07 = Arrays.copyOfRange(rndA, 2, 8);
        log(methodName, printData("rndA     ", rndA), false);
        log(methodName, printData("rndA02to07", rndA02to07), false);
        rndB00to05 = Arrays.copyOfRange(rndB, 0, 6);
        log(methodName, printData("rndB     ", rndB), false);
        log(methodName, printData("rndB00to05", rndB00to05), false);
        byte[] xored = xor(rndA02to07, rndB00to05);
        log(methodName, printData("xored     ", xored), false);
        System.arraycopy(xored, 0, cmacInput, 8, 6);
        System.arraycopy(rndB, 6, cmacInput, 14, 10);
        System.arraycopy(rndA, 8, cmacInput, 24, 8);

        log(methodName, printData("rndA     ", rndA), false);
        log(methodName, printData("rndB     ", rndB), false);
        log(methodName, printData("cmacInput", cmacInput), false);
        byte[] iv = new byte[16];
        log(methodName, printData("iv       ", iv), false);
        byte[] cmac = calculateDiverseKey(authenticationKey, cmacInput);
        log(methodName, printData("cmacOut ", cmac), false);
        return cmac;
    }

    public byte[] getSesSDMFileReadMACKey(byte[] sdmFileReadKey, byte[] uid, byte[] sdmReadCounter) {
        // see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 15 - 18
        final String methodName = "getSesSDMFileReadMACKey";
        log(methodName, printData("sdmFileReadKey", sdmFileReadKey) + printData(" uid", uid) + printData(" sdmReadCounter", sdmReadCounter), true);
        // sanity checks
        if ((sdmFileReadKey == null) || (sdmFileReadKey.length != 16)) {
            log(methodName, "sdmFileReadKey is NULL or wrong length, aborted");
            return null;
        }
        if ((uid == null) || (uid.length != 7)) {
            log(methodName, "uid is NULL or wrong length, aborted");
            return null;
        }
        if ((sdmReadCounter == null) || (sdmReadCounter.length != 3)) {
            log(methodName, "sdmReadCounter is NULL or wrong length, aborted");
            return null;
        }
        // CMAC calculation when CMACInputOffset = CMACOffset
        byte[] cmacInput = new byte[16];
        byte[] labelSdmMac = new byte[]{(byte) (0x3C), (byte) (0xC3)}; // fixed to 0x3CC3
        byte[] counter = new byte[]{(byte) (0x00), (byte) (0x01)}; // fixed to 0x0001
        byte[] length = new byte[]{(byte) (0x00), (byte) (0x80)}; // fixed to 0x0080
        System.arraycopy(labelSdmMac, 0, cmacInput, 0, 2);
        System.arraycopy(counter, 0, cmacInput, 2, 2);
        System.arraycopy(length, 0, cmacInput, 4, 2);
        System.arraycopy(uid, 0, cmacInput, 6, 7);
        System.arraycopy(sdmReadCounter, 0, cmacInput, 13, 3);
        // todo this method is working only when UID and readCtr are present, if not the byte array is filled up with 00 to 16 bytes
        log(methodName, printData("cmacInput", cmacInput));
        byte[] cmac = calculateDiverseKey(sdmFileReadKey, cmacInput);
        log(methodName, printData("cmacOutput", cmac));
        return cmac;
    }

    public byte[] getSdmMac(byte[] sesSDMFileReadMACKey) {
        // see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 15 - 18
        final String methodName = "getSdmMac";
        log(methodName, printData("sesSDMFileReadMACKey", sesSDMFileReadMACKey), true);
        // sanity checks
        if ((sesSDMFileReadMACKey == null) || (sesSDMFileReadMACKey.length != 16)) {
            log(methodName, "sesSDMFileReadMACKey is NULL or wrong length, aborted");
            return null;
        }
        return calculateDiverseKey(sesSDMFileReadMACKey, new byte[0]);
    }

    public byte[] calculateDiverseKey(byte[] masterKey, byte[] input) {
        Log.d(TAG, "calculateDiverseKey" + printData(" masterKey", masterKey) + printData(" input", input));
        AesCmac mac = null;
        try {
            mac = new AesCmac();
            SecretKey key = new SecretKeySpec(masterKey, "AES");
            mac.init(key);  //set master key
            mac.updateBlock(input); //given input
            //for (byte b : input) System.out.print(" " + b);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                 InvalidKeyException e) {
            Log.e(TAG, "Exception on calculateDiverseKey: " + e.getMessage());
            return null;
        }
        return mac.doFinal();
    }

    private byte[] truncateMAC(byte[] fullMAC) {
        final String methodName = "truncateMAC";
        log(methodName, printData("fullMAC", fullMAC), true);
        if ((fullMAC == null) || (fullMAC.length < 2)) {
            log(methodName, "fullMAC is NULL or of wrong length, aborted");
            return null;
        }
        int fullMACLength = fullMAC.length;
        byte[] truncatedMAC = new byte[fullMACLength / 2];
        int truncatedMACPos = 0;
        for (int i = 1; i < fullMACLength; i += 2) {
            truncatedMAC[truncatedMACPos] = fullMAC[i];
            truncatedMACPos++;
        }
        log(methodName, printData("truncatedMAC", truncatedMAC));
        return truncatedMAC;
    }

    private byte[] xor(byte[] dataA, byte[] dataB) {
        log("xor", printData("dataA", dataA) + printData(" dataB", dataB), true);
        if ((dataA == null) || (dataB == null)) {
            Log.e(TAG, "xor - dataA or dataB is NULL, aborted");
            return null;
        }
        // sanity check - both arrays need to be of the same length
        int dataALength = dataA.length;
        int dataBLength = dataB.length;
        if (dataALength != dataBLength) {
            Log.e(TAG, "xor - dataA and dataB lengths are different, aborted (dataA: " + dataALength + " dataB: " + dataBLength + " bytes)");
            return null;
        }
        for (int i = 0; i < dataALength; i++) {
            dataA[i] ^= dataB[i];
        }
        return dataA;
    }


    private void invalidateAllData() {
        authenticateEv2FirstSuccess = false;
        authenticateEv2NonFirstSuccess = false;
        keyNumberUsedForAuthentication = -1;
        SesAuthENCKey = null; // filled by authenticateAesEv2First
        SesAuthMACKey = null; // filled by authenticateAesEv2First
        CmdCounter = 0; // filled / resetted by authenticateAesEv2First
        TransactionIdentifier = null; // resetted by authenticateAesEv2First
    }

    private void invalidateAllDataNonFirst() {
        // authenticateEv2FirstSuccess = false; skip out, is necessary for the NonFirst method
        authenticateEv2NonFirstSuccess = false;
        keyNumberUsedForAuthentication = -1;
        SesAuthENCKey = null; // filled by authenticateAesEv2First
        SesAuthMACKey = null; // filled by authenticateAesEv2First
        //CmdCounter = 0; // filled / resetted by authenticateAesEv2First
        //TransactionIdentifier = null; // resetted by authenticateAesEv2First
    }

    /**
     * checks if the response has an 0x'9100' at the end means success
     * and the method returns the data without 0x'9100' at the end
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return
     */
    private boolean checkResponse(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        if (Arrays.equals(RESPONSE_OK, returnStatusBytes(data))) {
            return true;
        } else {
            return false;
        }
    }

    private boolean checkResponseIso(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        if (Arrays.equals(RESPONSE_ISO_OK, returnStatusBytes(data))) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * checks if the response has an 0x'91AF' at the end means success
     * but there are more data frames available
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return
     */
    private boolean checkResponseMoreData(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        if (Arrays.equals(RESPONSE_MORE_DATA_AVAILABLE, returnStatusBytes(data))) {
            return true;
        } else {
            return false;
        }
    }

    private byte[] returnStatusBytes(byte[] data) {
        return Arrays.copyOfRange(data, (data.length - 2), data.length);
    }

    /**
     * Returns a copy of the data bytes in the response body. If this APDU as
     * no body, this method returns a byte array with a length of zero.
     *
     * @return a copy of the data bytes in the response body or the empty
     * byte array if this APDU has no body.
     */
    private byte[] getData(byte[] responseAPDU) {
        byte[] data = new byte[responseAPDU.length - 2];
        System.arraycopy(responseAPDU, 0, data, 0, data.length);
        return data;
    }

    /**
     * sendRequest is a one byte command without parameter
     * @param command
     * @return
     * @throws Exception
     */
    private byte[] sendRequest(byte command) throws Exception {
        return sendRequest(command, null);
    }

    /**
     * sendRequest is sending a command to the PICC and depending on response code it finish or may
     * asking for more data ("code AF = additional frame available)
     * @param command
     * @param parameters
     * @return
     * @throws Exception
     */

    private byte[] sendRequest(byte command, byte[] parameters) throws Exception {
        String methodName = "sendRequest";
        Log.d(TAG, methodName + " command: " + Utils.byteToHex(command) + printData(" parameters", parameters));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        //byte[] recvBuffer = isoDep.transceive(wrapMessage(command, parameters));
        byte[] recvBuffer = sendData(wrapMessage(command, parameters));
        while (true) {
            if (recvBuffer[recvBuffer.length - 2] != (byte) 0x91) {
                throw new Exception("Invalid response");
            }
            output.write(recvBuffer, 0, recvBuffer.length - 2);
            byte status = recvBuffer[recvBuffer.length - 1];
            if (status == OPERATION_OK) {
                break;
            } else if (status == ADDITIONAL_FRAME) {
                recvBuffer = isoDep.transceive(wrapMessage(GET_ADDITIONAL_FRAME_COMMAND, null));
            } else if (status == PERMISSION_DENIED) {
                throw new AccessControlException("Permission denied");
            } else if (status == AUTHENTICATION_ERROR) {
                throw new AccessControlException("Authentication error");
            } else {
                throw new Exception("Unknown status code: " + Integer.toHexString(status & 0xFF));
            }
        }
        return output.toByteArray();
    }

    private byte[] wrapMessage(byte command, byte[] parameters) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write((byte) 0x90);
        stream.write(command);
        stream.write((byte) 0x00);
        stream.write((byte) 0x00);
        if (parameters != null) {
            stream.write((byte) parameters.length);
            stream.write(parameters);
        }
        stream.write((byte) 0x00);
        return stream.toByteArray();
    }

    private byte[] sendData(byte[] apdu) {
        String methodName = "sendData";
        if (isoDep == null) {
            Log.e(TAG, methodName + " isoDep is NULL");
            log(methodName, "isoDep is NULL, aborted");
            return null;
        }
        log(methodName, printData("send apdu -->", apdu));
        byte[] recvBuffer;
        try {
            recvBuffer = isoDep.transceive(apdu);
        } catch (IOException e) {
            errorCodeReason = "IOException: " + e.getMessage();
            Log.e(TAG, e.getMessage());
            e.printStackTrace();
            return null;
        }
        log(methodName, printData("received  <--", recvBuffer));
        return recvBuffer;
    }

    /**
     * section for UI related tasks
     */

    private void writeToUiAppend(TextView textView, String message) {
        activity.runOnUiThread(() -> {
            String oldString = textView.getText().toString();
            if (TextUtils.isEmpty(oldString)) {
                textView.setText(message);
            } else {
                String newString = message + "\n" + oldString;
                textView.setText(newString);
                System.out.println(message);
            }
        });
    }

    private void log(String methodName, String data) {
        log(methodName, data, false);
    }

    private void log(String methodName, String data, boolean isMethodHeader) {
        if (printToLog) {
            //logData += "method: " + methodName + "\n" + data + "\n";
            logData += "\n" + methodName + ":\n" + data + "\n\n";
            Log.d(TAG, "method: " + methodName + ": " + data);
        }
    }

    /**
     * getter
     */

    public byte[] getErrorCode() {
        return errorCode;
    }

    public String getErrorCodeReason() {
        return errorCodeReason;
    }

    public String getLogData() {
        return logData;
    }

    public byte[] getNTAG_424_DNA_DF_APPLICATION_NAME() {
        return NTAG_424_DNA_DF_APPLICATION_NAME;
    }

    public byte getKeyNumberUsedForAuthentication() {
        return keyNumberUsedForAuthentication;
    }

    public byte[] getSesAuthENCKey() {
        return SesAuthENCKey;
    }

    public byte[] getSesAuthMACKey() {
        return SesAuthMACKey;
    }

    public int getCmdCounter() {
        return CmdCounter;
    }

    public byte[] getTransactionIdentifier() {
        return TransactionIdentifier;
    }
}
