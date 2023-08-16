package de.androidcrypto.talktoyourntag424dnacard;

import static de.androidcrypto.talktoyourntag424dnacard.Utils.hexStringToByteArray;
import static de.androidcrypto.talktoyourntag424dnacard.Utils.hexStringToByteArrayMinus;
import static de.androidcrypto.talktoyourntag424dnacard.Utils.intFrom3ByteArrayInversed;
import static de.androidcrypto.talktoyourntag424dnacard.Utils.intTo2ByteArrayInversed;
import static de.androidcrypto.talktoyourntag424dnacard.Utils.intTo3ByteArrayInversed;
import static de.androidcrypto.talktoyourntag424dnacard.Utils.printData;

import android.app.Activity;
import android.nfc.Tag;
import android.nfc.TagLostException;
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

import de.androidcrypto.talktoyourntag424dnacard.lrp.LrpCipher;
import de.androidcrypto.talktoyourntag424dnacard.lrp.LrpMultiCipher;

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
GetKeyVersion                      90  64 CommMode.Plain         implemented
GetKeyVersion                      90  64 CommMode.MAC
GetVersion - Part1                 90  60 CommMode.Plain         implemented
GetVersion - Part2                 90  AF CommMode.Plain         implemented
GetVersion - Part3                 90  AF CommMode.Plain         implemented
GetVersion - Part1                 90  60 CommMode.MAC [1]
GetVersion - Part2                 90  AF CommMode.MAC [1]
GetVersion - Part3                 90  AF CommMode.MAC [1]
ISOReadBinary                      00  B0 CommMode.Plain
ReadData                           90  AD Comm. mode of targeted file
ReadData                           90  AD CommMode.Plain         implemented
ReadData                           90  AD CommMode.MAC
ReadData                           90  AD CommMode.Full          implemented
Read_Sig                           90  3C CommMode.Full
ISOSelectFile                      00  A4 CommMode.Plain
SetConfiguration                   90  5C CommMode.Full
ISOUpdateBinary                    00  D6 CommMode.Plain
WriteData                          90  8D Comm. mode of targeted file
WriteData                          90  8D CommMode.Plain         ???
WriteData                          90  8D CommMode.MAC
WriteData                          90  8D CommMode.Full          implemented
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
     * variables in this section are used in LRP mode
     */

    private List<byte[]> secretPlaintexts00; // pre generated per application key, here for application key 00 // 'SesAuthSPT'
    private List<byte[]> updateKeys00; // pre generated per application key, here for application key 00 // 'AuthUpdateKey'

    private byte[] SesAuthMaster; // pre generated per application key, here for application key 00



    /**
     * the CommunicationAdapter is initialized on initializing this class
     */

    CommunicationAdapterNtag424Dna communicationAdapter;

    /**
     * constants
     */

    private static final byte CHANGE_KEY_SECURE_COMMAND = (byte) 0xC4;
    private static final byte GET_VERSION_INFO_COMMAND = (byte) 0x60;
    private static final byte GET_KEY_VERSION_COMMAND = (byte) 0x64;
    private static final byte GET_ADDITIONAL_FRAME_COMMAND = (byte) 0xAF;
    private static final byte SELECT_APPLICATION_ISO_COMMAND = (byte) 0xA4;
    private static final byte GET_FILE_SETTINGS_COMMAND = (byte) 0xF5;
    private static final byte CHANGE_FILE_SETTINGS_COMMAND = (byte) 0x5F;
    private static final byte READ_STANDARD_FILE_COMMAND = (byte) 0xAD; // different to DESFire !
    private static final byte READ_STANDARD_FILE_SECURE_COMMAND = (byte) 0xAD;
    private static final byte WRITE_STANDARD_FILE_SECURE_COMMAND = (byte) 0x8D;
    private static final byte AUTHENTICATE_EV2_FIRST_COMMAND = (byte) 0x71;
    private static final byte AUTHENTICATE_EV2_NON_FIRST_COMMAND = (byte) 0x77;
    private static final byte SET_CONFIGURATION_COMMAND = (byte) 0x5C;

    /**
     * NTAG 424 DNA specific constants
     */

    public final byte[] NTAG_424_DNA_DF_APPLICATION_NAME = Utils.hexStringToByteArray("D2760000850101");
    public static final byte STANDARD_FILE_NUMBER_01 = (byte) 0x01;
    public static final byte STANDARD_FILE_NUMBER_02 = (byte) 0x02;
    public static final byte STANDARD_FILE_NUMBER_03 = (byte) 0x03;

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
    private static final byte[] RESPONSE_PARAMETER_ERROR = new byte[]{(byte) 0x91, (byte) 0xFE}; // failure because of wrong parameter
    private static final byte[] RESPONSE_FAILURE = new byte[]{(byte) 0x91, (byte) 0xFF}; // general, undefined failure


    private static final byte[] RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS = new byte[]{(byte) 0x91, (byte) 0xFD};
    private static final byte[] RESPONSE_FAILURE_MISSING_AUTHENTICATION = new byte[]{(byte) 0x91, (byte) 0xFE};
    private static final byte[] HEADER_ENC = new byte[]{(byte) (0x5A), (byte) (0xA5)}; // fixed to 0x5AA5
    private static final byte[] HEADER_MAC = new byte[]{(byte) (0xA5), (byte) (0x5A)}; // fixed to 0x5AA5

    // constants for LRP mode
    private static final byte[] LRP_FIXED_COUNTER = new byte[]{(byte) (0x00), (byte) (0x01)}; // fixed to 0x0001
    private static final byte[] LRP_FIXED_LENGTH = new byte[]{(byte) (0x00), (byte) (0x80)}; // fixed to 0x0080
    private static final byte[] LRP_FIXED_LABEL = new byte[]{(byte) (0x96), (byte) (0x69)}; // fixed to 0x9669


    private static final byte[] PADDING_FULL = hexStringToByteArray("80000000000000000000000000000000");

    public enum CommunicationSettings {
        Plain, MACed, Full
    }

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
     *
     * @return the analyzed version information class
     * <p>
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
     *
     * @param dfApplicationName
     * @return Note: The NTAG 424 DNA has ONE pre defined application with name "D2760000850101"
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
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
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
        fileSettings[0] = new FileSettings(STANDARD_FILE_NUMBER_01, getFileSettings(STANDARD_FILE_NUMBER_01));
        if (Arrays.equals(errorCode, RESPONSE_LENGTH_ERROR)) {
            // this is the strange behaviour, get the fileSettings again
            fileSettings[0] = new FileSettings(STANDARD_FILE_NUMBER_01, getFileSettings(STANDARD_FILE_NUMBER_01));
        }
        fileSettings[1] = new FileSettings(STANDARD_FILE_NUMBER_02, getFileSettings(STANDARD_FILE_NUMBER_02));
        fileSettings[2] = new FileSettings(STANDARD_FILE_NUMBER_03, getFileSettings(STANDARD_FILE_NUMBER_03));
        return fileSettings;
    }

    /**
     * reads the fileSettings of a file and returns a byte array that length depends on settings on
     * Secure Dynamic Messaging (SDM) - if enabled the length is longer than 7 bytes (disabled SDM)
     *
     * @param fileNumber
     * @return see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 26-27
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
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
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
     * changes the fileSettings of the file
     * @param fileNumber            : in range 1..3
     * @param communicationSettings : Plain, MACed or Full
     * @param keyRW                 : keyNumber in range 0..4 or 14 ('E', free) or 15 ('F', never)
     * @param keyCar                : see keyRW
     * @param keyR                  : see keyRW
     * @param keyW                  : see keyRW
     * @param sdmEnable             : true = enables SDM and mirroring
     * @return                      : true on success
     *
     * Note on SDM enabling: this will set some predefined, fixed values, that work with the sample NDEF string
     * https://choose.url.com/ntag424?e=00000000000000000000000000000000&c=0000000000000000
     * taken from NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf page 31
     * - communicationSettings: Plain
     * - enabling SDM and mirroring
     * - sdmOptions are '0xC1' (UID mirror: 1, SDMReadCtr: 1, SDMReadCtrLimit: 0, SDMENCFileData: 0, ASCII Encoding mode: 1
     * - SDMAccessRights are '0xF121':
     *   0xF: RFU
     *   0x1: FileAR.SDMCtrRet
     *   0x2: FileAR.SDMMetaRead
     *   0x1: FileAR.SDMFileRead
     * - Offsets:
     *   ENCPICCDataOffset: 0x200000
     *   SDMMACOffset:      0x430000
     *   SDMMACInputOffset: 0x430000
     */

    public boolean changeFileSettings(byte fileNumber, CommunicationSettings communicationSettings, int keyRW, int keyCar, int keyR, int keyW, boolean sdmEnable) {

        // this method can only enable Secure Dynamic Message but cannot set specific data like offsets
        // see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 34 - 35 for SDM example
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 65 - 69 for fields and errors
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 69 - 70 for getFileSettings with responses incl. SDM
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 71 - 72 for getFileCounters
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 23 - 25 for general workflow with FULL communication

        // status: WORKING on enabling and disabling SDM feature

        String logData = "";
        final String methodName = "changeFileSettings";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        // sanity checks
        errorCode = new byte[2];
        // sanity checks
        if (keyRW < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyRW is < 0, aborted";
            return false;
        }
        if ((keyRW > 4) & (keyRW != 14) & (keyRW != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyRW is > 4 but not 14 or 15, aborted";
            return false;
        }
        if (keyCar < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyCar is < 0, aborted";
            return false;
        }
        if ((keyCar > 4) & (keyCar != 14) & (keyCar != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyCar is > 4 but not 14 or 15, aborted";
            return false;
        }
        if (keyR < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyR is < 0, aborted";
            return false;
        }
        if ((keyR > 4) & (keyR != 14) & (keyR != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyR is > 4 but not 14 or 15, aborted";
            return false;
        }
        if (keyW < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyW is < 0, aborted";
            return false;
        }
        if ((keyW > 4) & (keyW != 14) & (keyW != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyW is > 4 but not 14 or 15, aborted";
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "isoDep is NULL (maybe it is not a NTAG424DNA tag ?), aborted";
            return false;
        }
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            errorCode = RESPONSE_FAILURE_MISSING_AUTHENTICATION.clone();
            errorCodeReason = "missing authentication, did you forget to authenticate with the application Master key (0x00) ?), aborted";
            return false;
        }

        if (sdmEnable) {
            Log.d(TAG, "enabling Secure Dynamic Messaging feature on NTAG 424 DNA");
            if (fileNumber != 2) {
                errorCode = RESPONSE_PARAMETER_ERROR.clone();
                errorCodeReason = "sdmEnable works on fileNumber 2 only, aborted";
                return false;
            }
        }

/*
fileNumber: 01
fileType: 0 (Standard)
communicationSettings: 00 (Plain)
accessRights RW | CAR: 00
accessRights R  | W:   E0
accessRights RW:       0
accessRights CAR:      0
accessRights R:        14
accessRights W:        0
fileSize: 32
--------------
fileNumber: 02
fileType: 0 (Standard)
communicationSettings: 00 (Plain)
accessRights RW | CAR: E0
accessRights R  | W:   EE
accessRights RW:       14
accessRights CAR:      0
accessRights R:        14
accessRights W:        14
fileSize: 256
--------------
fileNumber: 03
fileType: 0 (Standard)
communicationSettings: 03 (Encrypted)
accessRights RW | CAR: 30
accessRights R  | W:   23
accessRights RW:       3
accessRights CAR:      0
accessRights R:        2
accessRights W:        3
fileSize: 128
         */

        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        // Generating the MAC for the Command APDU
        byte[] commandCounterLsb = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb", commandCounterLsb));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(HEADER_MAC, 0, HEADER_MAC.length);
        baosIvInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosIvInput.write(commandCounterLsb, 0, commandCounterLsb.length);
        baosIvInput.write(padding1, 0, padding1.length);
        byte[] ivInput = baosIvInput.toByteArray();
        log(methodName, printData("ivInput", ivInput));

        // IV for CmdData = Enc(KSesAuthENC, IV_Input)
        log(methodName, printData("SesAuthENCKey", SesAuthENCKey));
        byte[] startingIv = new byte[16];
        byte[] ivForCmdData = AES.encrypt(startingIv, SesAuthENCKey, ivInput);
        log(methodName, printData("ivForCmdData", ivForCmdData));

        // build the command data
        byte communicationSettingsByte = (byte) 0x00;
        if (communicationSettings.name().equals(CommunicationSettings.Plain.name())) communicationSettingsByte = (byte) 0x00;
        if (communicationSettings.name().equals(CommunicationSettings.MACed.name())) communicationSettingsByte = (byte) 0x01;
        if (communicationSettings.name().equals(CommunicationSettings.Full.name())) communicationSettingsByte = (byte) 0x03;
        byte fileOption;
        if (sdmEnable) {
            fileOption = (byte) 0x40; // enable SDM and mirroring, Plain communication
        } else {
            fileOption = communicationSettingsByte;
        }
        byte accessRightsRwCar = (byte) ((keyRW << 4) | (keyCar & 0x0F)); // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) ((keyR << 4) | (keyW & 0x0F)) ; // Read Access & Write Access
        byte sdmOptions = (byte) 0xC1; // UID mirror = 1, SDMReadCtr = 1, SDMReadCtrLimit = 0, SDMENCFileData = 0, ASCII Encoding mode = 1
        byte[] sdmAccessRights = hexStringToByteArray("F121");
        byte[] ENCPICCDataOffset = Utils.intTo3ByteArrayInversed(32); // 0x200000
        byte[] SDMMACOffset = Utils.intTo3ByteArrayInversed(67);      // 0x430000
        byte[] SDMMACInputOffset = Utils.intTo3ByteArrayInversed(67); // 0x430000
        ByteArrayOutputStream baosCommandData = new ByteArrayOutputStream();
        baosCommandData.write(fileOption);
        baosCommandData.write(accessRightsRwCar);
        baosCommandData.write(accessRightsRW);
        // following data are written on sdmEnable only
        if (sdmEnable) {
            baosCommandData.write(sdmOptions);
            baosCommandData.write(sdmAccessRights, 0, sdmAccessRights.length);
            baosCommandData.write(ENCPICCDataOffset, 0, ENCPICCDataOffset.length);
            baosCommandData.write(SDMMACOffset, 0, SDMMACOffset.length);
            baosCommandData.write(SDMMACInputOffset, 0, SDMMACInputOffset.length);
        }
        byte[] commandData = baosCommandData.toByteArray();
        log(methodName, printData("commandData", commandData));

        /*
from: NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf page 34
CmdData example: 4000E0C1F121200000430000430000
40 00E0 C1 F121 200000 430000 430000
40h = FileOption (SDM and
Mirroring enabled), CommMode: plain
00E0h = AccessRights (FileAR.ReadWrite: 0x0, FileAR.Change: 0x0, FileAR.Read: 0xE, FileAR.Write; 0x0)
C1h =
• UID mirror: 1
• SDMReadCtr: 1
• SDMReadCtrLimit: 0
• SDMENCFileData: 0
• ASCII Encoding mode: 1
F121h = SDMAccessRights (RFU: 0xF, FileAR.SDMCtrRet = 0x1, FileAR.SDMMetaRead: 0x2, FileAR.SDMFileRead: 0x1)
200000h = ENCPICCDataOffset
430000h = SDMMACOffset
430000h = SDMMACInputOffset
 */

        // eventually some padding is necessary with 0x80..00
        byte[] commandDataPadded = paddingWriteData(commandData);
        log(methodName, printData("commandDataPadded", commandDataPadded));

        // E(KSesAuthENC, IVc, CmdData || Padding (if necessary))
        byte[] encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, commandDataPadded);
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        // Cmd || CmdCounter || TI || CmdHeader = fileNumber || E(KSesAuthENC, CmdData)
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(CHANGE_FILE_SETTINGS_COMMAND); // 0x5F
        baosMacInput.write(commandCounterLsb, 0, commandCounterLsb.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(fileNumber);
        baosMacInput.write(encryptedData, 0, encryptedData.length);
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));

        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // error in DESFire Light Features and Hints, page 57, point 28:
        // Data (FileNo || Offset || DataLength || Data) is NOT correct, as well not the Data Message
        // correct is the following concatenation:

        // Data (CmdHeader = fileNumber || Encrypted Data || MAC)
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        baosWriteDataCommand.write(fileNumber);
        baosWriteDataCommand.write(encryptedData, 0, encryptedData.length);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] writeDataCommand = baosWriteDataCommand.toByteArray();
        log(methodName, printData("writeDataCommand", writeDataCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(CHANGE_FILE_SETTINGS_COMMAND, writeDataCommand);
/*
from NTAG424DNA sheet page 69:
PERMISSION_DENIED
- 9Dh PICC level (MF) is selected.
- access right Change of targeted file has access conditions set to Fh.
- Enabling Secure Dynamic Messaging (FileOption Bit 6 set to 1b) is only allowed for FileNo 02h.
 */
            // expected APDU 905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400 (31 bytes)
            response = sendData(apdu);
        } catch (IOException e) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: " + e.getMessage();
            return false;
        }
        if (!checkResponse(response)) {
            log(methodName, methodName + " FAILURE");
            byte[] responseBytes = returnStatusBytes(response);
            System.arraycopy(responseBytes, 0, errorCode, 0, 2);
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);

        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    public boolean changeFileSettings(byte fileNumber, CommunicationSettings communicationSettings, int keyRW, int keyCar, int keyR, int keyW, boolean sdmEnable, int encPiccDataOffset, int sdmMacOffset, int sdmMacInputOffset) {

        // this method can only enable Secure Dynamic Message but cannot set specific data like offsets
        // see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 34 - 35 for SDM example
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 65 - 69 for fields and errors
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 69 - 70 for getFileSettings with responses incl. SDM
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 71 - 72 for getFileCounters
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 23 - 25 for general workflow with FULL communication

        // status: WORKING on enabling and disabling SDM feature

        String logData = "";
        final String methodName = "changeFileSettings";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        // sanity checks
        errorCode = new byte[2];
        // sanity checks
        if (keyRW < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyRW is < 0, aborted";
            return false;
        }
        if ((keyRW > 4) & (keyRW != 14) & (keyRW != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyRW is > 4 but not 14 or 15, aborted";
            return false;
        }
        if (keyCar < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyCar is < 0, aborted";
            return false;
        }
        if ((keyCar > 4) & (keyCar != 14) & (keyCar != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyCar is > 4 but not 14 or 15, aborted";
            return false;
        }
        if (keyR < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyR is < 0, aborted";
            return false;
        }
        if ((keyR > 4) & (keyR != 14) & (keyR != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyR is > 4 but not 14 or 15, aborted";
            return false;
        }
        if (keyW < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyW is < 0, aborted";
            return false;
        }
        if ((keyW > 4) & (keyW != 14) & (keyW != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyW is > 4 but not 14 or 15, aborted";
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "isoDep is NULL (maybe it is not a NTAG424DNA tag ?), aborted";
            return false;
        }
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            errorCode = RESPONSE_FAILURE_MISSING_AUTHENTICATION.clone();
            errorCodeReason = "missing authentication, did you forget to authenticate with the application Master key (0x00) ?), aborted";
            return false;
        }

        if (sdmEnable) {
            Log.d(TAG, "enabling Secure Dynamic Messaging feature on NTAG 424 DNA");
            if (fileNumber != 2) {
                errorCode = RESPONSE_PARAMETER_ERROR.clone();
                errorCodeReason = "sdmEnable works on fileNumber 2 only, aborted";
                return false;
            }
        }

        // todo validate offsets

/*
fileNumber: 01
fileType: 0 (Standard)
communicationSettings: 00 (Plain)
accessRights RW | CAR: 00
accessRights R  | W:   E0
accessRights RW:       0
accessRights CAR:      0
accessRights R:        14
accessRights W:        0
fileSize: 32
--------------
fileNumber: 02
fileType: 0 (Standard)
communicationSettings: 00 (Plain)
accessRights RW | CAR: E0
accessRights R  | W:   EE
accessRights RW:       14
accessRights CAR:      0
accessRights R:        14
accessRights W:        14
fileSize: 256
--------------
fileNumber: 03
fileType: 0 (Standard)
communicationSettings: 03 (Encrypted)
accessRights RW | CAR: 30
accessRights R  | W:   23
accessRights RW:       3
accessRights CAR:      0
accessRights R:        2
accessRights W:        3
fileSize: 128
         */

        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        // Generating the MAC for the Command APDU
        byte[] commandCounterLsb = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb", commandCounterLsb));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(HEADER_MAC, 0, HEADER_MAC.length);
        baosIvInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosIvInput.write(commandCounterLsb, 0, commandCounterLsb.length);
        baosIvInput.write(padding1, 0, padding1.length);
        byte[] ivInput = baosIvInput.toByteArray();
        log(methodName, printData("ivInput", ivInput));

        // IV for CmdData = Enc(KSesAuthENC, IV_Input)
        log(methodName, printData("SesAuthENCKey", SesAuthENCKey));
        byte[] startingIv = new byte[16];
        byte[] ivForCmdData = AES.encrypt(startingIv, SesAuthENCKey, ivInput);
        log(methodName, printData("ivForCmdData", ivForCmdData));

        // build the command data
        byte communicationSettingsByte = (byte) 0x00;
        if (communicationSettings.name().equals(CommunicationSettings.Plain.name())) communicationSettingsByte = (byte) 0x00;
        if (communicationSettings.name().equals(CommunicationSettings.MACed.name())) communicationSettingsByte = (byte) 0x01;
        if (communicationSettings.name().equals(CommunicationSettings.Full.name())) communicationSettingsByte = (byte) 0x03;
        byte fileOption;
        if (sdmEnable) {
            fileOption = (byte) 0x40; // enable SDM and mirroring, Plain communication
        } else {
            fileOption = communicationSettingsByte;
        }
        byte accessRightsRwCar = (byte) ((keyRW << 4) | (keyCar & 0x0F)); // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) ((keyR << 4) | (keyW & 0x0F)) ; // Read Access & Write Access
        byte sdmOptions = (byte) 0xC1; // UID mirror = 1, SDMReadCtr = 1, SDMReadCtrLimit = 0, SDMENCFileData = 0, ASCII Encoding mode = 1
        byte[] sdmAccessRights = hexStringToByteArray("F121");
        byte[] ENCPICCDataOffset = Utils.intTo3ByteArrayInversed(encPiccDataOffset); // e.g. 0x200000 for NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf example on pages 31 + 34
        byte[] SDMMACOffset = Utils.intTo3ByteArrayInversed(sdmMacOffset);      // e.g. 0x430000
        byte[] SDMMACInputOffset = Utils.intTo3ByteArrayInversed(sdmMacInputOffset); // e.g. 0x430000
        log(methodName, printData("ENCPICCDataOffset", ENCPICCDataOffset));
        log(methodName, printData("SDMMACOffset     ", SDMMACOffset));
        log(methodName, printData("SDMMACInputOffset", SDMMACInputOffset));
        /*
        values using server data: https://sdm.nfcdeveloper.com/tag
        ENCPICCDataOffset length: 3 data: 2a0000 (42d)
        SDMMACOffset      length: 3 data: 500000 (80d)
        SDMMACInputOffset length: 3 data: 500000 (80d)

         */
        ByteArrayOutputStream baosCommandData = new ByteArrayOutputStream();
        baosCommandData.write(fileOption);
        baosCommandData.write(accessRightsRwCar);
        baosCommandData.write(accessRightsRW);
        // following data are written on sdmEnable only
        if (sdmEnable) {
            baosCommandData.write(sdmOptions);
            baosCommandData.write(sdmAccessRights, 0, sdmAccessRights.length);
            baosCommandData.write(ENCPICCDataOffset, 0, ENCPICCDataOffset.length);
            baosCommandData.write(SDMMACOffset, 0, SDMMACOffset.length);
            baosCommandData.write(SDMMACInputOffset, 0, SDMMACInputOffset.length);
        }
        byte[] commandData = baosCommandData.toByteArray();
        log(methodName, printData("commandData", commandData));

        /*
from: NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf page 34
CmdData example: 4000E0C1F121200000430000430000
40 00E0 C1 F121 200000 430000 430000
40h = FileOption (SDM and
Mirroring enabled), CommMode: plain
00E0h = AccessRights (FileAR.ReadWrite: 0x0, FileAR.Change: 0x0, FileAR.Read: 0xE, FileAR.Write; 0x0)
C1h =
• UID mirror: 1
• SDMReadCtr: 1
• SDMReadCtrLimit: 0
• SDMENCFileData: 0
• ASCII Encoding mode: 1
F121h = SDMAccessRights (RFU: 0xF, FileAR.SDMCtrRet = 0x1, FileAR.SDMMetaRead: 0x2, FileAR.SDMFileRead: 0x1)
200000h = ENCPICCDataOffset
430000h = SDMMACOffset
430000h = SDMMACInputOffset
 */

        // eventually some padding is necessary with 0x80..00
        byte[] commandDataPadded = paddingWriteData(commandData);
        log(methodName, printData("commandDataPadded", commandDataPadded));

        // E(KSesAuthENC, IVc, CmdData || Padding (if necessary))
        byte[] encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, commandDataPadded);
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        // Cmd || CmdCounter || TI || CmdHeader = fileNumber || E(KSesAuthENC, CmdData)
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(CHANGE_FILE_SETTINGS_COMMAND); // 0x5F
        baosMacInput.write(commandCounterLsb, 0, commandCounterLsb.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(fileNumber);
        baosMacInput.write(encryptedData, 0, encryptedData.length);
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));

        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // error in DESFire Light Features and Hints, page 57, point 28:
        // Data (FileNo || Offset || DataLength || Data) is NOT correct, as well not the Data Message
        // correct is the following concatenation:

        // Data (CmdHeader = fileNumber || Encrypted Data || MAC)
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        baosWriteDataCommand.write(fileNumber);
        baosWriteDataCommand.write(encryptedData, 0, encryptedData.length);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] writeDataCommand = baosWriteDataCommand.toByteArray();
        log(methodName, printData("writeDataCommand", writeDataCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(CHANGE_FILE_SETTINGS_COMMAND, writeDataCommand);
/*
from NTAG424DNA sheet page 69:
PERMISSION_DENIED
- 9Dh PICC level (MF) is selected.
- access right Change of targeted file has access conditions set to Fh.
- Enabling Secure Dynamic Messaging (FileOption Bit 6 set to 1b) is only allowed for FileNo 02h.
 */
            // expected APDU 905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400 (31 bytes)
            response = sendData(apdu);
        } catch (IOException e) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: " + e.getMessage();
            return false;
        }
        if (!checkResponse(response)) {
            log(methodName, methodName + " FAILURE");
            byte[] responseBytes = returnStatusBytes(response);
            System.arraycopy(responseBytes, 0, errorCode, 0, 2);
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);

        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    public boolean changeFileSettingsOrg(byte fileNumber, CommunicationSettings communicationSettings, int keyRW, int keyCar, int keyR, int keyW, boolean sdmEnable) {

        // this method can only enable Secure Dynamic Message but cannot set specific data like offsets
        // see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 34 - 35 for SDM example
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 65 - 69 for fields and errors


        // status: NOT WORKING
        // eventually the file needs to get the sdm options on setup even if disabled
        // todo check with real tag if fileSettings are "prepared" for SDM usage

        // see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 34 - 35 for SDM example
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 65 - 69 for fields and errors
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 69 - 70 for getFileSettings with responses incl. SDM
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 71 - 72 for getFileCounters
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 23 - 25 for general workflow with FULL communication

        // see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 34 - 35
        // Change NDEF file settings using Cmd.ChangeFileSettings using CommMode.Full
        // this is based on the changeFileSettings on a NTAG 424 DNA tag

        String logData = "";
        final String methodName = "changeFileSettings";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        // sanity checks
        // sanity checks
        errorCode = new byte[2];
        // sanity checks
        if (keyRW < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyRW is < 0, aborted";
            return false;
        }
        if ((keyRW > 4) & (keyRW != 14) & (keyRW != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyRW is > 4 but not 14 or 15, aborted";
            return false;
        }
        if (keyCar < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyCar is < 0, aborted";
            return false;
        }
        if ((keyCar > 4) & (keyCar != 14) & (keyCar != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyCar is > 4 but not 14 or 15, aborted";
            return false;
        }
        if (keyR < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyR is < 0, aborted";
            return false;
        }
        if ((keyR > 4) & (keyR != 14) & (keyR != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyR is > 4 but not 14 or 15, aborted";
            return false;
        }
        if (keyW < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyW is < 0, aborted";
            return false;
        }
        if ((keyW > 4) & (keyW != 14) & (keyW != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyW is > 4 but not 14 or 15, aborted";
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "isoDep is NULL (maybe it is not a NTAG424DNA tag ?), aborted";
            return false;
        }
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            errorCode = RESPONSE_FAILURE_MISSING_AUTHENTICATION.clone();
            errorCodeReason = "missing authentication, did you forget to authenticate with the application Master key (0x00) ?), aborted";
            return false;
        }

/*
        final byte[] file01_fileSettings = hexStringToByteArray("000000e0200000");
        final byte[] file02_fileSettings = hexStringToByteArray("0000e0ee000100");
        final byte[] file03_fileSettings = hexStringToByteArray("00033023800000");
        final byte[] file03_fileSettings = hexStringToByteArray("00 03 3023 80 0000");
        00 = file type = standard file
        03 = communication mode = full (00 = plain, 01 = MAC)
        3023 = access rights RW || Car || R || W
        80 00 00 = file size (LSB, 128 decimal)
        final byte defaultKeyVersion = (byte) 0x00; // valid for all 5 application keys
        final byte[] defaultApplicationKey = new byte[16]; // valid for all 5 application keys
*/
/*
fileNumber: 01
fileType: 0 (Standard)
communicationSettings: 00 (Plain)
accessRights RW | CAR: 00
accessRights R  | W:   E0
accessRights RW:       0
accessRights CAR:      0
accessRights R:        14
accessRights W:        0
fileSize: 32
--------------
fileNumber: 02
fileType: 0 (Standard)
communicationSettings: 00 (Plain)
accessRights RW | CAR: E0
accessRights R  | W:   EE
accessRights RW:       14
accessRights CAR:      0
accessRights R:        14
accessRights W:        14
fileSize: 256
--------------
fileNumber: 03
fileType: 0 (Standard)
communicationSettings: 03 (Encrypted)
accessRights RW | CAR: 30
accessRights R  | W:   23
accessRights RW:       3
accessRights CAR:      0
accessRights R:        2
accessRights W:        3
fileSize: 128
         */

        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        // Generating the MAC for the Command APDU
        byte[] commandCounterLsb = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb", commandCounterLsb));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(HEADER_MAC, 0, HEADER_MAC.length);
        baosIvInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosIvInput.write(commandCounterLsb, 0, commandCounterLsb.length);
        baosIvInput.write(padding1, 0, padding1.length);
        byte[] ivInput = baosIvInput.toByteArray();
        log(methodName, printData("ivInput", ivInput));

        // IV for CmdData = Enc(KSesAuthENC, IV_Input)
        log(methodName, printData("SesAuthENCKey", SesAuthENCKey));
        byte[] startingIv = new byte[16];
        byte[] ivForCmdData = AES.encrypt(startingIv, SesAuthENCKey, ivInput);
        log(methodName, printData("ivForCmdData", ivForCmdData));

        // build the command data
        byte communicationSettingsByte = (byte) 0x00;
        if (communicationSettings.name().equals(CommunicationSettings.Plain.name())) communicationSettingsByte = (byte) 0x00;
        if (communicationSettings.name().equals(CommunicationSettings.MACed.name())) communicationSettingsByte = (byte) 0x01;
        if (communicationSettings.name().equals(CommunicationSettings.Full.name())) communicationSettingsByte = (byte) 0x03;
        byte fileOption = (byte) 0x40; // enable SDM and mirroring, Plain communication
        byte accessRightsRwCar = (byte) ((keyRW << 4) | (keyCar & 0x0F)); // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) ((keyR << 4) | (keyW & 0x0F)) ; // Read Access & Write Access
        byte sdmOptions = (byte) 0xC1; // UID mirror = 1, SDMReadCtr = 1, SDMReadCtrLimit = 0, SDMENCFileData = 0, ASCII Encoding mode = 1
        byte[] sdmAccessRights = hexStringToByteArray("F121");
        ByteArrayOutputStream baosCommandData = new ByteArrayOutputStream();
        //baosCommandData.write((byte) 0x00); // fileType 00, fixed
        //baosCommandData.write(communicationSettingsByte); // this is the  fileOptions byte
        baosCommandData.write(fileOption);
        baosCommandData.write(accessRightsRwCar);
        baosCommandData.write(accessRightsRW);
        baosCommandData.write(sdmOptions);
        baosCommandData.write(sdmAccessRights, 0, sdmAccessRights.length);
        byte[] commandData = baosCommandData.toByteArray();

        // build the cmdData, is a bit complex due to a lot of options - here it is shortened
        //byte[] commandData = hexStringToByteArray ("4000E0C1F121200000430000430000"); // feature & hints
        //byte[] commandData = hexStringToByteArray("40EEEEC1F121200000500000500000"); // this is the data of the working TapLinx command

        log(methodName, printData("commandData", commandData));
/*
from: NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf page 34
CmdData example: 4000E0C1F121200000430000430000
40 00E0 C1 F121 200000 430000 430000
40h = FileOption (SDM and
Mirroring enabled), CommMode: plain
00E0h = AccessRights (FileAR.ReadWrite: 0x0, FileAR.Change: 0x0, FileAR.Read: 0xE, FileAR.Write; 0x0)
C1h =
• UID mirror: 1
• SDMReadCtr: 1
• SDMReadCtrLimit: 0
• SDMENCFileData: 0
• ASCII Encoding mode: 1
F121h = SDMAccessRights (RFU: 0xF, FileAR.SDMCtrRet = 0x1, FileAR.SDMMetaRead: 0x2, FileAR.SDMFileRead: 0x1)
200000h = ENCPICCDataOffset
430000h = SDMMACOffset
430000h = SDMMACInputOffset
 */

        // eventually some padding is necessary with 0x80..00

        // this is from https://community.nxp.com/t5/NFC/NTAG-424-DNA-Change-NDEF-File-Settings-problem/td-p/1328599
        // 40 00 E0 D1 F1 21 1F 00 00 44 00 00 44 00 00 40 00 00 8A 00 00 80 00 00 00 00 00 00 00 00 00 00
        // 4000E0D1F1211F00004400004400004000008A00008000000000000000000000

        // our fix commandData from example has 15 bytes so we do need 16 bytes
        //byte[] commandDataPadded = hexStringToByteArray("40EEEEC1F12120000050000050000080");
        //byte[] commandDataPadded = hexStringToByteArray ("40EEEEC1F12120000043000043000080");
        //byte[] commandDataPadded = hexStringToByteArray("4000E0D1F1211F00004400004400004000008A00008000000000000000000000");

        // this is the commandPadded from working TapLinx example
        //byte[] commandDataPadded = hexStringToByteArray("40EEEEC1F1212A000050000050000080");
        byte[] commandDataPadded = paddingWriteData(commandData);

        // this is the command from working TapLinx example
        //byte[] commandDataPadded = hexStringToByteArray("40EEEEC1F12120000032000045000080");

        log(methodName, printData("commandDataPadded", commandDataPadded));

        // E(KSesAuthENC, IVc, CmdData || Padding (if necessary))
        byte[] encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, commandDataPadded);
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        // Cmd || CmdCounter || TI || CmdHeader = fileNumber || E(KSesAuthENC, CmdData)
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(CHANGE_FILE_SETTINGS_COMMAND); // 0x5F
        baosMacInput.write(commandCounterLsb, 0, commandCounterLsb.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(fileNumber);
        baosMacInput.write(encryptedData, 0, encryptedData.length);
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));

        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // error in Features and Hints, page 57, point 28:
        // Data (FileNo || Offset || DataLenght || Data) is NOT correct, as well not the Data Message
        // correct is the following concatenation:

        // Data (CmdHeader = fileNumber || Encrypted Data || MAC)
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        baosWriteDataCommand.write(fileNumber);
        baosWriteDataCommand.write(encryptedData, 0, encryptedData.length);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] writeDataCommand = baosWriteDataCommand.toByteArray();
        log(methodName, printData("writeDataCommand", writeDataCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(CHANGE_FILE_SETTINGS_COMMAND, writeDataCommand); //0261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A04 25d = 19b
            // comApdu       905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400
            // my apdu       905f00001902d7bff30bb6d212e512ddf49942a754f7003b5d104371344200

            // when I append sample data this change
            // gives error   9D Permission denied error
/*
from NTAG424DNA sheet page 69:
PERMISSION_DENIED
- 9Dh PICC level (MF) is selected.
- access right Change of targeted file has access conditions set to Fh.
- Enabling Secure Dynamic Messaging (FileOption Bit 6 set to 1b) is only allowed for FileNo 02h.
 */
            // expected APDU 905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400 (31 bytes)
            response = sendData(apdu);
        } catch (IOException e) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: " + e.getMessage();
            return false;
        }
        if (!checkResponse(response)) {
            log(methodName, methodName + " FAILURE");
            byte[] responseBytes = returnStatusBytes(response);
            System.arraycopy(responseBytes, 0, errorCode, 0, 2);
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);

        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    public FileSettings[] getAllFileSettingsMac() {
        // returns the fileSettings of all 3 pre installed files on NTAG 424 DNA
        FileSettings[] fileSettings = new FileSettings[3];
        /**
         * found a strange behaviour on the getFileSettings: after a (successful) authentication the first
         * getFileSettings command returns an 0x7e = 'length error', so in case of an error I'm trying to
         * get the file settings a second time
         */
        fileSettings[0] = new FileSettings(STANDARD_FILE_NUMBER_01, getFileSettingsMac(STANDARD_FILE_NUMBER_01));
        if (Arrays.equals(errorCode, RESPONSE_LENGTH_ERROR)) {
            // this is the strange behaviour, get the fileSettings again
            fileSettings[0] = new FileSettings(STANDARD_FILE_NUMBER_01, getFileSettingsMac(STANDARD_FILE_NUMBER_01));
        }
        fileSettings[1] = new FileSettings(STANDARD_FILE_NUMBER_02, getFileSettingsMac(STANDARD_FILE_NUMBER_02));
        fileSettings[2] = new FileSettings(STANDARD_FILE_NUMBER_03, getFileSettingsMac(STANDARD_FILE_NUMBER_03));
        return fileSettings;
    }

    /**
     * reads the fileSettings of a file and returns a byte array that length depends on settings on
     * Secure Dynamic Messaging (SDM) - if enabled the length is longer than 7 bytes (disabled SDM)
     * This method is verifying a received MAC
     * @param fileNumber
     * @return see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 26-27
     */
    public byte[] getFileSettingsMac(byte fileNumber) {
        String logData = "";

        // status NOT working

        final String methodName = "getFileSettingsMac";
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
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "fileNumber is not in range 1..3, aborted";
            return null;
        }
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return null;
        }

        // MAC_Input
        // Cmd || CmdCounter || TI || CmdHeader = fileNumber || n/a (CmdData)
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(READ_STANDARD_FILE_SECURE_COMMAND); // 0xAD
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(fileNumber);
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

        // Constructing the full getFileSettings Command APDU
        ByteArrayOutputStream baosGetFileSettingsCommand = new ByteArrayOutputStream();
        baosGetFileSettingsCommand.write(fileNumber);
        baosGetFileSettingsCommand.write(macTruncated, 0, macTruncated.length);
        byte[] getFileSettingsCommand = baosGetFileSettingsCommand.toByteArray();
        log(methodName, printData("getFileSettingsCommand", getFileSettingsCommand));

        byte[] apdu = new byte[0];
        byte[] response;
        try {
            apdu = wrapMessage(GET_FILE_SETTINGS_COMMAND, getFileSettingsCommand);
            response = sendData(apdu);
        } catch (IOException e) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: " + e.getMessage();
            return null;
        }
        if (!checkResponse(response)) {
            log(methodName, methodName + " FAILURE");
            byte[] responseBytes = returnStatusBytes(response);
            System.arraycopy(responseBytes, 0, errorCode, 0, 2);
            errorCodeReason = methodName + " FAILURE";
            return null;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        // response length: 58 data: 8b61541d54f73901c8498c71dd45bae80578c4b1581aad439a806f37517c86ad4df8970279bbb8874ef279149aaa264c3e5eceb0e37a87699100

        // the fullResponseData is xx bytes fileSettings || 8 bytes MAC
        byte[] fullResponseData = Arrays.copyOf(response, response.length - 2);
        int responseDataLength = fullResponseData.length - 8;
        log(methodName, "The fullResponseData is of length " + fullResponseData.length + " that includes 8 bytes for MAC");
        log(methodName, "The responseData length is " + responseDataLength);
        byte[] responseData = Arrays.copyOfRange(fullResponseData, 0, responseDataLength);
        byte[] responseMACTruncatedReceived = Arrays.copyOfRange(fullResponseData, responseDataLength, fullResponseData.length);
        log(methodName, printData("responseData", responseData));
        if (verifyResponseMac(responseMACTruncatedReceived, responseData)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return responseData;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " FAILURE";
            return null;
        }
    }

    /**
     * Note: to run LRP tasks the PICC has to be in LRP mode. You can find code for this mode
     * in Mifare DESFire Light Features and Hints AN12343.pdf pages 43 + 44
     * This is an IRREVERSIBLE action and PERMANENTLY disables AES secure messaging, meaning
     * LRP secure messaging is required to be used for all future sessions.
     * As I'm on limited resources (number of DESFire EV2/EV3 tags I'm skipping any experiments
     * on this feature,sorry.
     *
     * see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 24
     * (Table 18 Secure messaging mode negotiation)
     *
     * Reader is asking the mode    || PICC is in mode xx and answers as follows
     * PCD is requesting | PDCap2.1 || PDCap2    | PICC answers       | Comments
     * mode:             | value    || value     |                    |
     * ------------------|----------||-----------|--------------------|-------------------------
     * EV2 Secure        |   00h    || 00h (AES) | 17 bytes with AFh  | reader and PICC use AES
     * Messaging (AES)   |          ||           | (16 bytes rndB)    |
     * ------------------|----------||-----------|--------------------|-------------------------
     * EV2 Secure        |   00h    || 02h (LRP) | Permission denied  | no authentication
     * Messaging (AES)   |          ||           |                    | available possible
     * ------------------|----------||-----------|--------------------|-------------------------
     * ------------------|----------||-----------|--------------------|-------------------------
     * LRP Secure        |   02h    || 00h (AES) | 1 byte with AFh    | no authentication but
     * Messaging         |          ||           |                    | reader can use AES next
     * ------------------|----------||-----------|--------------------|-------------------------
     * LRP Secure        |   02h    || 02h (LRP) | 18 bytes with AFh  | reader and PICC use LRP
     * Messaging         |          ||           | (1 byte auth mode  |
     *                   |          ||           | (16 bytes rndB     |
     * ------------------|----------||-----------|--------------------|-------------------------
     *
     * So in short: you can test LRP when PICC is in LRP mode only
     *
     */

    public boolean authenticateLrpEv2First(byte keyNo, byte[] key) {

        /**
         * see MIFARE DESFire Light contactless application IC.pdf, pages 37 ff and 55ff
         * see pages 44 ff for detailed example
         * SessionKeys example: pages 48 - 50
         *
         * MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 57 - 60
         *
         * Purpose: To start a new transaction
         * Capability Bytes: PCD and PICC capability bytes are exchanged (PDcap2, PCDcap2)
         * Transaction Identifier: A new transaction identifier is generated which remains valid for the full transaction
         * Command Counter: CmdCtr is reset to 0x0000
         * Session Keys: New session keys are generated
         */

        // see example in Mifare DESFire Light Features and Hints AN12343.pdf pages 33 ff
        // and MIFARE DESFire Light contactless application IC MF2DLHX0.pdf pages 52 ff
        boolean testMode = true;
        logData = "";
        invalidateAllData();
        final String methodName = "authenticateLrpEv2First";
        log(methodName, printData("key", key) + " keyNo: " + keyNo, true);
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

        if (testMode) {
            Log.d(TAG, "** authenticateLrpEv2First test mode ENABLED **");
            log(methodName, "** authenticateLrpEv2First test mode ENABLED **");
            //keyNo = (byte) 0x03; // is this correct ?
            keyNo = (byte) 0x00;
            key = hexStringToByteArray("00000000000000000000000000000000");
        }

        log(methodName, "step 01 get encrypted rndB from card", false);
        log(methodName, "This method is using the AUTHENTICATE_AES_EV2_FIRST_COMMAND so it will work with AES-based applications only", false);
        // authenticate 1st part
        byte[] apdu;
        byte[] response = new byte[0];
        try {
            /**
             * note: the parameter needs to be a 2 byte long value, the first one is the key number and the second
             * one could any LEN capability ??
             * I'm setting the byte[] to keyNo | 0x00
             */
            byte LRP_INDICATOR = (byte) 0x02;
            byte[] PCDCAP_2_1 = new byte[5];
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(keyNo);
            baos.write((byte) 0x06); // length of following cap (LenCap)
            baos.write(LRP_INDICATOR);
            baos.write(PCDCAP_2_1, 0, PCDCAP_2_1.length);
            byte[] commandParameter = baos.toByteArray();
            log(methodName, printData("commandParameter", commandParameter));
            apdu = wrapMessage(AUTHENTICATE_EV2_FIRST_COMMAND, commandParameter);
            log(methodName, "get enc rndB " + printData("apdu", apdu));
            if (testMode) {
                byte[] apduExp = hexStringToByteArray("9071000008000602000000000000");
                if (!Arrays.equals(apdu, apduExp)) {
                    log(methodName, printData("apduExp", apduExp));
                    Log.e(TAG, "apdu does not match the expected value, aborted");
                    return false;
                }
                response = hexStringToByteArray("0156109A31977C855319CD4618C9D2AED291AF");
            } else {
                response = sendData(apdu);
            }
            log(methodName, "get enc rndB " + printData("response", response));
            // response: 013622ab415702ff1684c94fb2f9f517dc91af
            // response 01 = tag is in LRP mode || rndB (16 bytes) || status code (2 bytes)
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
            System.arraycopy(responseBytes, 0, errorCode, 0, 2);
            return false;
        }
        // response: 05e8942501c8349464eacb3811bf586a 91af (18 bytes)
        // PICC not in LRP mode - the tag answers with 16 bytes RndB || 91 AF
        // response is NOT: AuthMode || PICC challenge RndB || status code AF = more data
        // auth mode 01 means LRP mode, 00 is fall back to AES

        // response when PICC is in LRP mode:
        // 01 fb23fd204377069411f9dcea628d796 991af (19 bytes)
        // AuthMode (1 byte) || PICC challenge RndB (16 bytes) || status code AF = more data (2 bytes)
        byte[] rndB = Arrays.copyOfRange(getData(response), 1, response.length - 2);
        log(methodName, printData("rndB", rndB));

        // step 14: generate RndA
        byte[] rndA = new byte[16]; // this is an AES key
        rndA = getRandomData(rndA);
        if (testMode) {
            rndA = hexStringToByteArray("74D7DF6A2CEC0B72B412DE0D2B1117E6");
        }
        log(methodName, printData("rndA", rndA));

        // step 15: concatenate RndA || RndB = "dynamic data"
        // is done in next step

        // step 16 session vector (used for session key calculation)
        // is done in generateLrpSessionKeys()

        /*
        // fixed counter || fixed length || dynamic context || fixed label
        // 0001 || 0080 || dynamic data || 9669
        final byte[] FIXED_COUNTER = new byte[]{(byte) (0x00), (byte) (0x01)}; // fixed to 0x0001
        final byte[] FIXED_LENGTH = new byte[]{(byte) (0x00), (byte) (0x80)}; // fixed to 0x0080
        final byte[] FIXED_LABEL = new byte[]{(byte) (0x96), (byte) (0x69)}; // fixed to 0x9669
        // build the session vector
        ByteArrayOutputStream baosSessionVector = new ByteArrayOutputStream();
        baosSessionVector.write(FIXED_COUNTER, 0, FIXED_COUNTER.length);
        baosSessionVector.write(FIXED_LENGTH, 0, FIXED_LENGTH.length);
        baosSessionVector.write(rndA, 0, rndA.length);
        baosSessionVector.write(rndB, 0, rndB.length);
        baosSessionVector.write(FIXED_LABEL, 0, FIXED_LABEL.length);
        byte[] sessionVector = baosSessionVector.toByteArray();
        log(methodName, printData("sessionVector", sessionVector));
        if (testMode) {
            // 0001008074D7897AB6DD9C0E855319CD4618C9D2AED2B412DE0D2B1117E69669
            byte[] sessionVectorExp = hexStringToByteArray("0001008074D7897AB6DD9C0E855319CD4618C9D2AED2B412DE0D2B1117E69669");
            if (!Arrays.equals(sessionVector, sessionVectorExp)) {
                log(methodName, printData("sessionVectorExp", sessionVectorExp));
                Log.e(TAG, "sessionVector does not match the expected value, aborted");
                return false;
            }
            sessionVector = sessionVectorExp.clone();
        }
         */

        boolean sessionKeySuccess = generateLrpSessionKeys(rndA, rndB, key);


        // AuthenticateLRPFirst Part 2
        // step 19 (should be done BEFORE step 18 as in setp 18 the data is needed ??
        // step 19: PCDResponse = MAC_LRP (KSesAuthMACKey; RNDA || RNDB)
        // 89B59DCEDC31A3D3F38EF8D4810B3B4

        // step 18: Data = RndA || PCDResponse
        // 74D7DF6A2CEC0B72B412DE0D2B1117E689B59DCEDC31A3D3F38EF8D4810B3B4


/*
        // now we know that we can work with the response, 16 bytes long
        // R-APDU (Part 1) (E(Kx, RndB)) || SW1 || SW2
        //byte[] rndB_enc =  getData(response);
        byte[] rndB_enc = Arrays.copyOfRange(getData(response), 1, response.length - 2);
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

            // todo THIS step is FAILING with AE error

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
            System.arraycopy(responseBytes, 0, errorCode, 0, 2);
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
*/
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
/*
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

 */
        return false;
    }

    /**
     * calculate the LRP Session Keys (KeySets) during authenticateLrpEv2First
     * It uses the AesMac class for CMAC
     * The code is tested with example values in Mifare DESFire Light Features and Hints AN12343.pdf
     * on pages 46..50
     *
     * @param rndA              is the random generated 16 bytes long key A from reader
     * @param rndB              is the random generated 16 bytes long key B from PICC
     * @param authenticationKey is the 16 bytes long AES key used for authentication
     * @return the 16 bytes long (AES) encryption key
     */

    public boolean generateLrpSessionKeys(byte[] rndA, byte[] rndB, byte[] authenticationKey) {

        // see MIFARE DESFire Light contactless application IC pdf, pages 46 - 50
        final String methodName = "generateLrpSessionKeys";
        log(methodName, printData("rndA", rndA) + printData(" rndB", rndB) + printData(" authenticationKey", authenticationKey), true);
        // sanity checks
        if ((rndA == null) || (rndA.length != 16)) {
            log(methodName, "rndA is NULL or wrong length, aborted");
            return false;
        }
        if ((rndB == null) || (rndB.length != 16)) {
            log(methodName, "rndB is NULL or wrong length, aborted");
            return false;
        }
        if ((authenticationKey == null) || (authenticationKey.length != 16)) {
            log(methodName, "authenticationKey is NULL or wrong length, aborted");
            return false;
        }
        boolean TEST_MODE_GEN_LRP_SES_KEYS = true;

        if (TEST_MODE_GEN_LRP_SES_KEYS) {
            writeToUiAppend(textView, "### TEST_MODE enabled ###");
            writeToUiAppend(textView, "using pre defined values");
            rndA = Utils.hexStringToByteArray("74D7DF6A2CEC0B72B412DE0D2B1117E6");
            rndB = Utils.hexStringToByteArray("56109A31977C855319CD4618C9D2AED2");
            authenticationKey = Utils.hexStringToByteArray("00000000000000000000000000000000");
        }
        log(methodName, printData("rndA     ", rndA));
        // 74 D7 DF 6A 2C EC 0B 72 B4 12 DE 0D 2B 11 17 E6
        //  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
        byte[] rndA00to01 = Arrays.copyOfRange(rndA, 0, 2); // step 06 74d7
        byte[] rndA02to07 = Arrays.copyOfRange(rndA, 2, 8); // step 07 DF6A2CEC0B72
        byte[] rndA08to15 = Arrays.copyOfRange(rndA, 8, 16); // step 11 (wrong: 2B412DE0D2B1117E), correct B412DE0D2B1117E6
        // 56 10 9A 31 97 7C 85 53 19 CD 46 18 C9 D2 AE D2
        //  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
        byte[] rndB00to05 = Arrays.copyOfRange(rndB, 0, 6); // step 08 56109A31977C
        byte[] rndB06to15 = Arrays.copyOfRange(rndB, 6, 16); // step 10 855319CD4618C9D2AED2
        byte[] xored = xor(rndA02to07, rndB00to05); // step 09
        // step 12 sessionVector
        // counter || length tag || RndA[15::14] || (RndA[13::8] XOR RndB[15::10]) || RndB[9::0] || RndA[7::0] || label
        // counter || length tag || rndA00to01   || xored                          || rndB06to15 || rndA08to15 || label
        // 0001008074D7897AB6DD9C0E855319CD4618C9D2AED2B412DE0D2B1117E69669
        ByteArrayOutputStream baosSessionVector = new ByteArrayOutputStream();
        baosSessionVector.write(LRP_FIXED_COUNTER, 0, LRP_FIXED_COUNTER.length);
        baosSessionVector.write(LRP_FIXED_LENGTH, 0, LRP_FIXED_LENGTH.length);
        baosSessionVector.write(rndA00to01, 0, rndA00to01.length);
        baosSessionVector.write(xored, 0, xored.length);
        baosSessionVector.write(rndB06to15, 0, rndB06to15.length);
        baosSessionVector.write(rndA08to15, 0, rndA08to15.length);
        baosSessionVector.write(LRP_FIXED_LABEL, 0, LRP_FIXED_LABEL.length);
        byte[] sessionVector = baosSessionVector.toByteArray();
        if (TEST_MODE_GEN_LRP_SES_KEYS) {
            byte[] sessionVectorExp = hexStringToByteArray("0001008074D7897AB6DD9C0E855319CD4618C9D2AED2B412DE0D2B1117E69669");
            if (!Arrays.equals(sessionVector, sessionVectorExp)) {
                log(methodName, printData("sessionVectorExp", sessionVectorExp));
                Log.e(TAG, "sessionVector does not match the expected value, aborted");
                return false;
            } else {
                Log.d(TAG, "sessionVector test PASSED");
            }
        }

        // Generation of Secret Plaintexts for this Authentication (AuthSPT)
        // step 14: AuthSPT = generatePlaintexts(4, Kx)

        byte[] iv = new byte[16];
        // step 15: Round 1: Pre-Step: Length-doubling PRG - Updated key for 0x55
        // AES-Encrypt: EKx(0x55555555555555555555555555555555) = 9ADAE054F63DFAFF5EA18E45EDF6EA6F
        final byte[] data0x55 = hexStringToByteArray("55555555555555555555555555555555");
        byte[] updatedKey0x55 = AES.encrypt(iv, authenticationKey, data0x55);
        if (TEST_MODE_GEN_LRP_SES_KEYS) {
            byte[] updatedKey0x55Exp = hexStringToByteArray("9ADAE054F63DFAFF5EA18E45EDF6EA6F");
            if (!Arrays.equals(updatedKey0x55, updatedKey0x55Exp)) {
                log(methodName, printData("updatedKey0x55Exp", updatedKey0x55Exp));
                Log.e(TAG, "updatedKey0x55 does not match the expected value, aborted");
                return false;
            } else {
                Log.d(TAG, "updatedKey0x55 test PASSED");
            }
        }

        // step 16: Round 1: Pre-Step: Length-doubling PRG - Encryption of 0xAA
        // AES-Encrypt: EKx(0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA) = 8522717D3AD1FBFEAFA1CEAAFDF56565
        final byte[] data0xaa = hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        byte[] updatedKey0xaa = AES.encrypt(iv, authenticationKey, data0xaa);
        if (TEST_MODE_GEN_LRP_SES_KEYS) {
            byte[] updatedKey0xaaExp = hexStringToByteArrayMinus("8522717D3AD1FBFEAFA1CEAAFDF56565");
            if (!Arrays.equals(updatedKey0xaa, updatedKey0xaaExp)) {
                log(methodName, printData("updatedKey0xaaExp", updatedKey0xaaExp));
                Log.e(TAG, "updatedKey0xaa does not match the expected value, aborted");
                return false;
            } else {
                Log.d(TAG, "updatedKey0xaa test PASSED");
            }
        }

        if (TEST_MODE_GEN_LRP_SES_KEYS) {
            // see Leakage Resilient Primitive (LRP) Specification AN12304.pdf pages 10 ff
            // 3.1 LRP Eval in detail - 1. Test Vectors
            // Here, Base key refers to k in Algorithms 1 and 2. P[i] maps to pi in Algorithm 1 and
            // UK[i] maps to ki in Algorithm 2.

            // Generating Secret Plaintexts and Updated Keys
            byte[] tBaseKey = hexStringToByteArrayMinus("567826B8DA8E768432A9548DBE4AA3A0");
            // plaintext is data0x55
            byte[] t01Ciphertext = AES.encrypt(iv, tBaseKey, data0x55);
            byte[] t01CiphertextExp = hexStringToByteArrayMinus("3A-92-AA-06-40-F2-6A-E9-2F-81-99-36-52-F0-05-18");
            if (!compareArrays(t01Ciphertext, t01CiphertextExp, "t01Ciphertext"));
            // plaintext is data0xaa
            byte[] t02Ciphertext = AES.encrypt(iv, tBaseKey, data0xaa);
            byte[] t02CiphertextExp = hexStringToByteArrayMinus("22-DA-7A-8A-2F-4A-72-1D-43-EC-1C-97-02-FE-77-BE");
            if (!compareArrays(t02Ciphertext, t02CiphertextExp, "t02Ciphertext"));

            // Generating Secret Plaintexts
            // Plaintext base key = AES block key is t01Ciphertext
            // AES block plaintext is data0xaa
            // AES block ciphertext: AC-20-D3-9F-53-41-FE-98-DF-CA-21-DA-86-BA-79-14
            byte[] t03Ciphertext = AES.encrypt(iv, t01Ciphertext, data0xaa);
            byte[] t03CiphertextExp = hexStringToByteArrayMinus("AC-20-D3-9F-53-41-FE-98-DF-CA-21-DA-86-BA-79-14");
            if (!compareArrays(t03Ciphertext, t03CiphertextExp, "t03Ciphertext"));

            // P[0]: AC-20-D3-9F-53-41-FE-98-DF-CA-21-DA-86-BA-79-14 = t03Ciphertext
            byte[] tPlaintext0 = t03Ciphertext.clone();
            // AES block key is t01Ciphertext
            // Input plaintext is data0x55
            byte[] t04Ciphertext = AES.encrypt(iv, t01Ciphertext, data0x55);
            byte[] t04CiphertextExp = hexStringToByteArrayMinus("10-79-E9-6B-0E-24-61-C2-DE-AB-00-30-59-56-54-9A");
            if (!compareArrays(t04Ciphertext, t04CiphertextExp, "t04Ciphertext"));

            // Key for next secret plaintext generation: 10-79-E9-6B-0E-24-61-C2-DE-AB-00-30-59-56-54-9A
            // AES block key is t04Ciphertext
            // AES block plaintext is data0xaa
            byte[] t05Ciphertext = AES.encrypt(iv, t04Ciphertext, data0xaa);
            byte[] t05CiphertextExp = hexStringToByteArrayMinus("90-7D-A0-3D-67-24-49-16-69-15-E4-56-3E-08-9D-6D");
            if (!compareArrays(t05Ciphertext, t05CiphertextExp, "t05Ciphertext"));

            // P[1]: 90-7D-A0-3D-67-24-49-16-69-15-E4-56-3E-08-9D-6D = t05Ciphertext
            // AES block key is t04Ciphertext
            // Input plaintext is data0x55
            byte[] t06Ciphertext = AES.encrypt(iv, t04Ciphertext, data0x55);
            byte[] t06CiphertextExp = hexStringToByteArrayMinus("F9-A0-89-7A-D9-D3-76-BA-F7-88-6C-62-C8-E8-97-15");
            if (!compareArrays(t06Ciphertext, t06CiphertextExp, "t06Ciphertext"));

            // Key for next secret plaintext generation: F9-A0-89-7A-D9-D3-76-BA-F7-88-6C-62-C8-E8-97-15
            // AES block key is t06Ciphertext
            // AES block plaintext is data0xaa
            byte[] t07Ciphertext = AES.encrypt(iv, t06Ciphertext, data0xaa);
            byte[] t07CiphertextExp = hexStringToByteArrayMinus("92-FA-A8-B8-78-CC-D5-0C-63-13-DB-59-09-9D-CC-E8");
            if (!compareArrays(t07Ciphertext, t07CiphertextExp, "t07Ciphertext"));

            // P[2]: 92-FA-A8-B8-78-CC-D5-0C-63-13-DB-59-09-9D-CC-E8 = t07Ciphertext
            // AES block key is t06Ciphertext
            // Input plaintext is data0x55
            byte[] t08Ciphertext = AES.encrypt(iv, t06Ciphertext, data0x55);
            byte[] t08CiphertextExp = hexStringToByteArrayMinus("84-B8-14-14-BE-98-AD-7F-12-EE-F0-DD-1B-17-DF-FF");
            if (!compareArrays(t08Ciphertext, t08CiphertextExp, "t08Ciphertext"));

            // Key for next secret plaintext generation: 84-B8-14-14-BE-98-AD-7F-12-EE-F0-DD-1B-17-DF-FF
            // AES block key is t08Ciphertext
            // AES block plaintext is data0xaa
            byte[] t09Ciphertext = AES.encrypt(iv, t08Ciphertext, data0xaa);
            byte[] t09CiphertextExp = hexStringToByteArrayMinus("37-2F-A1-3D-D4-3E-FD-41-98-59-DC-BC-FC-EF-FB-F8");
            if (!compareArrays(t09Ciphertext, t09CiphertextExp, "t09Ciphertext"));

            // P3 = = t09Ciphertext
            byte[] t10Ciphertext = AES.encrypt(iv, t08Ciphertext, data0x55);
            byte[] t10CiphertextExp = hexStringToByteArrayMinus("02-0C-87-DA-40-8C-3C-8D-E2-C1-58-86-2B-09-B6-3D");
            if (!compareArrays(t10Ciphertext, t10CiphertextExp, "t10Ciphertext"));

            byte[] t11Ciphertext = AES.encrypt(iv, t10Ciphertext, data0xaa);
            byte[] t11CiphertextExp = hexStringToByteArrayMinus("5F-E2-E4-68-95-8B-6B-05-C8-A0-34-F3-38-23-CF-1B");
            if (!compareArrays(t11Ciphertext, t11CiphertextExp, "t11Ciphertext"));

            // P4 = = t11Ciphertext
            byte[] t12Ciphertext = AES.encrypt(iv, t10Ciphertext, data0x55);
            byte[] t12CiphertextExp = hexStringToByteArrayMinus("95-38-28-9A-9A-AC-5B-2D-B4-BB-76-F8-0F-B8-E8-5B");
            if (!compareArrays(t12Ciphertext, t12CiphertextExp, "t12Ciphertext"));

            byte[] t13Ciphertext = AES.encrypt(iv, t12Ciphertext, data0xaa);
            byte[] t13CiphertextExp = hexStringToByteArrayMinus("AB-75-E2-FA-6D-CC-BA-A0-4E-85-D0-7F-B9-4E-ED-28");
            if (!compareArrays(t13Ciphertext, t13CiphertextExp, "t13Ciphertext"));

            // P5 = = t13Ciphertext
            byte[] t14Ciphertext = AES.encrypt(iv, t12Ciphertext, data0x55);
            byte[] t14CiphertextExp = hexStringToByteArrayMinus("A9-ED-2B-3A-93-C5-07-D1-3C-28-C5-58-2F-C3-5E-12");
            if (!compareArrays(t14Ciphertext, t14CiphertextExp, "t14Ciphertext"));

            byte[] t15Ciphertext = AES.encrypt(iv, t14Ciphertext, data0xaa);
            byte[] t15CiphertextExp = hexStringToByteArrayMinus("AC-05-BC-DA-C4-4B-14-BF-FD-F8-90-74-98-69-53-89");
            if (!compareArrays(t15Ciphertext, t15CiphertextExp, "t15Ciphertext"));


            /**
             *
             * this is the complete workflow for setting up the keys for a real key
             * here shown solely for key 0x00
             *
             */
            secretPlaintexts00 = new ArrayList<>(); // clear the list
            updateKeys00 = new ArrayList<>(); // clear the list
            // we are starting with a BaseKey = the "real" application key
            // test vector taken from:
            // see Leakage Resilient Primitive (LRP) Specification AN12304.pdf pages 10 ff
            // 3.1 LRP Eval in detail - 1. Test Vectors
            // Here, Base key refers to k in Algorithms 1 and 2. P[i] maps to pi in Algorithm 1 and
            // UK[i] maps to ki in Algorithm 2.
            byte[] tBaseKey00 = hexStringToByteArrayMinus("567826B8DA8E768432A9548DBE4AA3A0"); //
            // we do have 2 input data:
            // byte[] data0x55 = hexStringToByteArray("55555555555555555555555555555555");
            // byte[] data0xaa = hexStringToByteArray("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

            byte[] baseKeyCiphertextForPlaintexts; // this key is the starting key for generating the 16 secret plaintexts
            baseKeyCiphertextForPlaintexts = AES.encrypt(iv, tBaseKey00, data0x55);

            // generate the 16 secret plaintext (AES keys)
            byte[] previousCiphertext55 = baseKeyCiphertextForPlaintexts.clone(); // init the key
            byte[] keyForNextSecretPlaintext;
            byte[] secretPlaintext;
            for (int i = 0; i < 16; i++) {
                secretPlaintext = AES.encrypt(iv, previousCiphertext55, data0xaa);
                log(methodName, "secretPlaintext " + i + printData(" secretPlaintext", secretPlaintext));
                secretPlaintexts00.add(secretPlaintext);
                keyForNextSecretPlaintext = AES.encrypt(iv, previousCiphertext55, data0x55);
                log(methodName, "keyForNextSecretPlaintext " + i + printData(" keyForNextSecretPlaintext", keyForNextSecretPlaintext));
                // this is the next starting key
                previousCiphertext55 = keyForNextSecretPlaintext.clone();
            }
            log(methodName, "-----------------------");
            byte[] secretPlaintext15 = secretPlaintexts00.get(15);
            byte[] secretPlaintext15Exp = hexStringToByteArrayMinus("71-B4-44-AF-25-7A-93-21-53-11-D7-58-DD-33-32-47");
            log(methodName, printData("secretPlaintext15", secretPlaintext15));
            if (!compareArrays(secretPlaintext15, secretPlaintext15Exp, "secretPlaintext15"));
            log(methodName, "-----------------------");

            // generate the update keys, similar to secret plaintexts
            byte[] baseKeyCiphertextForUpdateKey; // this key is the starting key for generating the update key
            baseKeyCiphertextForUpdateKey = AES.encrypt(iv, tBaseKey, data0xaa);

            byte[] previousCiphertextAa = baseKeyCiphertextForUpdateKey.clone();
            byte[] keyForNextUpdateKey;
            byte[] updateKey;
            for (int i = 0; i < 16; i++) {
                updateKey = AES.encrypt(iv, previousCiphertextAa, data0xaa);
                log(methodName, "updateKey " + i + printData(" updateKey", updateKey));
                updateKeys00.add(updateKey);
                keyForNextUpdateKey = AES.encrypt(iv, previousCiphertextAa, data0x55);
                log(methodName, "keyForNextUpdateKey " + i + printData(" keyForNextUpdateKey", keyForNextUpdateKey));
                // this is the next starting key
                previousCiphertextAa = keyForNextUpdateKey.clone();
            }
            log(methodName, "-----------------------");
            for (int i = 0; i < 16; i++) {
                byte[] updateKeyP = updateKeys00.get(i);
                //byte[] updateKey15Exp = hexStringToByteArrayMinus(""); // not known
                // updateKey 00, 01 + 02 equals to LRP document
                log(methodName, printData("updateKey " + i + ": ", updateKeyP));
            }
            log(methodName, "-----------------------");

            // I'm not for sure if we do need 16 update keys, Mifare DESFire Light Features and Hints AN12343.pdf
            // is just using updateKey00 for generating of SesAuthMaster and Session Keys

            // Mifare DESFire Light Features and Hints AN12343.pdf page 49
            log(methodName, "Generation of KSesAuthMaster");
            // test vectors
            rndA = hexStringToByteArray("74D7DF6A2CEC0B72B412DE0D2B1117E6");
            rndB = hexStringToByteArray("56109A31977C855319CD4618C9D2AED2");
            byte[] testSessionVector = getLrpSessionVector(rndA, rndB);
            log(methodName, printData("testSessionVector", testSessionVector));
            byte[] testSessionVectorExp = hexStringToByteArray("0001008074D7897AB6DD9C0E855319CD4618C9D2AED2B412DE0D2B1117E69669");
            compareArrays(testSessionVector, testSessionVectorExp, "testSessionVector");

            // Generation of KSesAuthMaster
            // KSesAuthMaster = CMAC-LRP(AuthUpdateKey, Session Vector)
            // Session vector is from the beginning:
            // counter || length tag || RndA[15::14] || (RndA[13::8] XOR RndB[15::10]) || RndB[9::0] || RndA[7::0] || label
            // CMAC_LRP(50A26CB5DF307E483DE532F6AFBEC27B, 0001008074d7897AB6DD9C0E855319CD4618C9D2AED2B412DE0D2B1117E69669) = 132D7E6F35BA861F39B37221214E25A5
            byte[] testUpdateKey = hexStringToByteArray("50A26CB5DF307E483DE532F6AFBEC27B");
            //byte[] testSesAuthMaster = calculateDiverseKey(testUpdateKey, testSessionVector);
            byte[] testSesAuthMaster = calculateDiverseKeyLrp(testUpdateKey, testSessionVector);
            byte[] testSesAuthMasterExp = hexStringToByteArray("132D7E6F35BA861F39B37221214E25A5");
            compareTestModeValues(testSesAuthMaster, testSesAuthMasterExp, "testSesAuthMaster");



        }


        // step 17: AuthSPT [0] = B5CBF983BBE3C458189436288813EC30

        // this is using the hardcoded LRP
        /*
        byte[] lrpKey = new byte[16];
        LrpMultiCipher mc = new LrpMultiCipher(lrpKey);
        // grab a cipher using key 1
        LrpCipher c =  mc.cipher(1);

        // Encrypt/Decrypt
        byte[] encryptedMessage = c.EncryptAll
*/


        // hard coded exit
        if (authenticationKey != null) return true;

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
        byte[] counter = new byte[]{(byte) (0x00), (byte) (0x01)}; // fixed to 0x0001
        byte[] length = new byte[]{(byte) (0x00), (byte) (0x80)}; // fixed to 0x0080

        System.arraycopy(HEADER_MAC, 0, cmacInput, 0, 2);
        System.arraycopy(counter, 0, cmacInput, 2, 2);
        System.arraycopy(length, 0, cmacInput, 4, 2);
        System.arraycopy(rndA, 0, cmacInput, 6, 2);


        rndA02to07 = Arrays.copyOfRange(rndA, 2, 8);
        log(methodName, printData("rndA     ", rndA));
        log(methodName, printData("rndA02to07", rndA02to07));
        rndB00to05 = Arrays.copyOfRange(rndB, 0, 6);
        log(methodName, printData("rndB     ", rndB));
        log(methodName, printData("rndB00to05", rndB00to05));

        log(methodName, printData("xored     ", xored));
        System.arraycopy(xored, 0, cmacInput, 8, 6);
        System.arraycopy(rndB, 6, cmacInput, 14, 10);
        System.arraycopy(rndA, 8, cmacInput, 24, 8);

        log(methodName, printData("rndA     ", rndA));
        log(methodName, printData("rndB     ", rndB));
        log(methodName, printData("cmacInput", cmacInput));
        if (TEST_MODE) {
            boolean testResult = compareTestModeValues(cmacInput, sv1_expected, "SV1");
        }

        log(methodName, printData("iv       ", iv));
        byte[] cmac = calculateDiverseKey(authenticationKey, cmacInput);
        log(methodName, printData("cmacOut ", cmac));
        if (TEST_MODE) {
            boolean testResult = compareTestModeValues(cmac, SesAuthENCKey_expected, "SesAUthENCKey");
        }
        return false;
    }

    /**
     * see scheme in Mifare DESFire Light Features and Hints AN12343.pdf page 38
     * @return
     */
    private byte[] calculateDiverseKeyLrp(byte[] key, byte[] iv) {
        // todo sanity checks
        byte[] loopIv = new byte[16];
        byte[] ciphertext = new byte[0];
        for (int i = 0; i < 16; i++) {
            byte[] plaintext = secretPlaintexts00.get(i);
            ciphertext = AES.encrypt(loopIv, key, plaintext);
            loopIv = ciphertext.clone();
        }
        return ciphertext;
    }


    private byte[] getLrpSessionVector(byte[] rndA, byte[] rndB) {
        String methodName = "getLrpSessionVector";
        // todo sanity checks
        log(methodName, printData("rndA        ", rndA));
        log(methodName, printData("rndB        ", rndB));

        // 74 D7 DF 6A 2C EC 0B 72 B4 12 DE 0D 2B 11 17 E6
        //  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
        byte[] rndA00to01 = Arrays.copyOfRange(rndA, 0, 2); // step 06 74d7
        byte[] rndA02to07 = Arrays.copyOfRange(rndA, 2, 8); // step 07 DF6A2CEC0B72
        byte[] rndA08to15 = Arrays.copyOfRange(rndA, 8, 16); // step 11 (wrong: 2B412DE0D2B1117E), correct B412DE0D2B1117E6
        // 56 10 9A 31 97 7C 85 53 19 CD 46 18 C9 D2 AE D2
        //  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
        byte[] rndB00to05 = Arrays.copyOfRange(rndB, 0, 6); // step 08 56109A31977C
        byte[] rndB06to15 = Arrays.copyOfRange(rndB, 6, 16); // step 10 855319CD4618C9D2AED2
        byte[] xored = xor(rndA02to07, rndB00to05); // step 09
        // step 12 sessionVector
        // counter || length tag || RndA[15::14] || (RndA[13::8] XOR RndB[15::10]) || RndB[9::0] || RndA[7::0] || label
        // counter || length tag || rndA00to01   || xored                          || rndB06to15 || rndA08to15 || label
        // 0001008074D7897AB6DD9C0E855319CD4618C9D2AED2B412DE0D2B1117E69669
        ByteArrayOutputStream baosSessionVector = new ByteArrayOutputStream();
        baosSessionVector.write(LRP_FIXED_COUNTER, 0, LRP_FIXED_COUNTER.length);
        baosSessionVector.write(LRP_FIXED_LENGTH, 0, LRP_FIXED_LENGTH.length);
        baosSessionVector.write(rndA00to01, 0, rndA00to01.length);
        baosSessionVector.write(xored, 0, xored.length);
        baosSessionVector.write(rndB06to15, 0, rndB06to15.length);
        baosSessionVector.write(rndA08to15, 0, rndA08to15.length);
        baosSessionVector.write(LRP_FIXED_LABEL, 0, LRP_FIXED_LABEL.length);
        byte[] sessionVector = baosSessionVector.toByteArray();
        log(methodName, printData("sessionVector", sessionVector));
        return sessionVector;
    }

    private boolean compareArrays (byte[] arr, byte[] arrExpected, String arrName) {
        String methodName = "compareArrays";
        if ((arr == null) || (arrExpected == null) || (arr.length < 1) || (arrExpected.length < 1)) {
            log(methodName, "arr or arrExpected are NULL or of length 0, aborted");
            Log.e(TAG, arrName + " arr or arrExpected are NULL or of length 0, aborted");
            return false;
        } else {
            if (!Arrays.equals(arr, arrExpected)) {
                log(methodName, printData(arrName + "   ", arr));
                log(methodName, printData(arrName + "Exp", arrExpected));
                Log.e(TAG, arrName + " does not match the expected value, aborted");
                return false;
            } else {
                Log.d(TAG, arrName + " test PASSED");
                return true;
            }
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
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyNumber is < 0, aborted";
            return false;
        }
        if (keyNo > 4) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyNumber is > 4, aborted";
            return false;
        }
        if ((key == null) || (key.length != 16)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "key length is not 16, aborted";
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "isoDep is NULL (maybe it is not a NTAG424DNA tag ?), aborted";
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "Authentication Error - did you use the wrong key ?";
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
            errorCode = RESPONSE_FAILURE_MISSING_AUTHENTICATION.clone();
            errorCodeReason = "missing previous successful authenticateEv2First, aborted";
            return false;
        }
        if (keyNo < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyNumber is < 0, aborted";
            return false;
        }
        if (keyNo > 4) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyNumber is > 4, aborted";
            return false;
        }
        if ((key == null) || (key.length != 16)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "key length is not 16, aborted";
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "isoDep is NULL (maybe it is not a NTAG424DNA tag ?), aborted";
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "Authentication Error - did you use the wrong key ?";
        }
        log(methodName, "*********************");
        return rndAEqual;
    }

    /**
     * There are 2 authentication mode available on a NTAG 424 DNA tag: AES and LRP (Leakage Resilient Primitive).
     * This is an irreversible action and permanently disables AES secure messaging, meaning
     * LRP secure messaging is required to be used for all future sessions.
     * Please use this method with care - there is no way back to AES secure messaging mode !
     * @return true on success
     * Note: A previous authentication using the Master Application Key (on a Mifare DESFire EVx tag)
     * or with the Application Master Key (on a NTAG 424 DNA) is necessary !
     */

    public boolean changeAuthenticationModeFromAesToLrp() {

        /**
         * see NTAG 424 DNA NT4H2421Gx.pdf 'SetConfiguration' command on pages 55 - 57
         * see Mifare DESFire Light Features and Hints AN12343.pdf pages 43 + 44 for example code
         * see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf 'SetConfiguration' command on pages 61 - 66
         */

        // status: WORKING

        boolean testMode = true; // if true some data is replaced by test vectors and no communication is done to the tag

        // at the moment this is just a stub with no action !

        String logData = "";
        final String methodName = "changeAuthenticationModeFromAesToLrp";
        log(methodName, "started", true);
        // sanity checks
        if (!checkAuthenticateAesEv2()) return false; // logFile and errorCode are updated
        if (!checkIsoDep()) return false; // logFile and errorCode are updated

        if (testMode) {
            Log.d(TAG, "** changeAuthenticationModeFromAesToLrp test mode ENABLED **");
            log(methodName, "** changeAuthenticationModeFromAesToLrp test mode ENABLED **");
            SesAuthENCKey = hexStringToByteArray("66A8CB93269DC9BC2885B7A91B9C697B");
            SesAuthMACKey = hexStringToByteArray("7DE5F7E244A46D22E536804D07E8D70E");
            TransactionIdentifier = hexStringToByteArray("ED56F6E6");
            CmdCounter = 0;
        }
        errorCode = RESPONSE_FAILURE.clone(); // default
        errorCodeReason = "TEST FAILURE";  // default
/*
3 Session MAC Key (SesAuthMACKey) =
4 Encrypting the Command Data
6 IV_Label =
7 TI =
8 Cmd Counter =
9 E(KSesAuthEnc, Basis for the IV)) =
10 IV =
11 PDCap2.1 =
12 Data for Cmd.SetConfiguration =
05 7DE5F7E244A46D22E536804D07E8D70E
A55A
ED56F6E6
0000 DA0F644A4986275957CF1EC3AF4CCE53 DA0F644A4986275957CF1EC3AF4CCE53 02
2
Session Encryption Key (SesAuthEncKey)
=
66A8CB93269DC9BC2885B7A91B9C697B
5
IV_Input
(IV_Label || TI || Cmd Counter || Padding)
=
A55A ED56F6E600000000000000000000
13 Padded Data
16 IV for MACing AN12343
Application note COMPANY PUBLIC
            00000000020000000000
= 00000000 02 0000000000 800000000000
= 00000000000000000000000000000000

17
MAC_Input
(Ins || Cmd Counter || TI || Cmd Header || Encrypted Data)
=
5C0000ED56F6E60541B2BA963075730426D0858D2AA6C498
5C 0000 ED56F6E6 05 41B2BA963075730426D0858D2AA6C498
18
MAC = CMAC(KSesAuthMAC, MAC_ Input)
=
2F579E77FAB49F83
19
Constructing the full Command APDU
20 CLA
21 Ins
22 P1
23 P2
24 Lc (Length of the data)
26 Le (Length expected)
28 Cmd Counter
29 Cmd.SetConfiguration R-APDU
= 90 = 5C = 00 = 00 = 19
= 00
25
Data (Cmd Header || Encrypted Data || MAC)
=
0541B2BA963075730426D0858D2AA6C4982F579E77FAB49F8 3
27
Cmd.SetConfiguration C-APDU
(Cmd || Ins || P1 || P2 || Lc || Data || Le)
>
905C000019050041B2BA963075730426D0858D2AA6C4982F579E77FAB49F8300
= 0100
< 9100 (00 = SUCCESS)
 */
        // Encrypting the Command Data
        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        // MAC_Input
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(HEADER_MAC, 0, HEADER_MAC.length);
        baosIvInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosIvInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosIvInput.write(padding1, 0, padding1.length);
        byte[] ivInput = baosIvInput.toByteArray();
        log(methodName, printData("ivInput", ivInput));

        // IV for CmdData = Enc(KSesAuthENC, IV_Input)
        log(methodName, printData("SesAuthENCKey", SesAuthENCKey));
        byte[] startingIv = new byte[16];
        byte[] ivForCmdData = AES.encrypt(startingIv, SesAuthENCKey, ivInput);
        log(methodName, printData("ivForCmdData", ivForCmdData));
        if (testMode) {
            byte[] ivForCmdDataExp = hexStringToByteArray("DA0F644A4986275957CF1EC3AF4CCE53");
            if (!Arrays.equals(ivForCmdData, ivForCmdDataExp)) {
                Log.e(TAG, "ivForCmdData does not match the expected value, aborted");
                return false;
            }
        }

        // command data - usually it is by by several parameter, but here we are just take the
        // original command sequence from the "Feature and Hint" document:
        byte[] commandDataPadded = hexStringToByteArray("00000000020000000000800000000000");
        log(methodName, printData("commandDataPadded", commandDataPadded));
        byte[] encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, commandDataPadded);
        log(methodName, printData("encryptedData", encryptedData));
        if (testMode) {
            byte[] encryptedDataExp = hexStringToByteArray("41B2BA963075730426D0858D2AA6C498");
            if (!Arrays.equals(encryptedData, encryptedDataExp)) {
                log(methodName, printData("encryptedDataExp", encryptedDataExp));
                Log.e(TAG, "encryptedData does not match the expected value, aborted");
                return false;
            }
        }

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader = 0x05 || Encrypted CmdData )
        byte CMD_HEADER = (byte) 0x05; // option 05 is targeted
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(SET_CONFIGURATION_COMMAND); // 0x5C
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(CMD_HEADER);
        baosMacInput.write(encryptedData, 0, encryptedData.length);
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));
        if (testMode) {
            byte[] macInputExp = hexStringToByteArray("5C0000ED56F6E60541B2BA963075730426D0858D2AA6C498");
            if (!Arrays.equals(macInput, macInputExp)) {
                Log.e(TAG, "macInput does not match the expected value, aborted");
                return false;
            }
        }

        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));
        if (testMode) {
            byte[] macTruncatedExp = hexStringToByteArray("2F579E77FAB49F83");
            if (!Arrays.equals(macTruncated, macTruncatedExp)) {
                Log.e(TAG, "macTruncated does not match the expected value, aborted");
                return false;
            }
        }

        // Data (CmdHeader || Encrypted Data || MAC)
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        baosWriteDataCommand.write(CMD_HEADER);
        baosWriteDataCommand.write(encryptedData, 0, encryptedData.length);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] writeDataCommand = baosWriteDataCommand.toByteArray();
        log(methodName, printData("SetConfigurationCommand", writeDataCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(SET_CONFIGURATION_COMMAND, writeDataCommand);
            if (testMode) {
                /**
                 * The apduExp in the DESFire Light Hints & Feature is WRONG
                 * When using the shortened version (without '00' after '05') it works
                 */
                // is this value (apduExp) correct ? The step 25 (Data (Cmd Header || Encrypted Data || MAC)) is showing this data:
                //                                                    0541B2BA963075730426D0858D2AA6C4982F579E77FAB49F83
                byte[] apduExp = hexStringToByteArray("905C000019050041B2BA963075730426D0858D2AA6C4982F579E77FAB49F8300");
                // changing to this apduExp, then command is running with success :
                apduExp = hexStringToByteArray("905C0000190541B2BA963075730426D0858D2AA6C4982F579E77FAB49F8300");
                if (!Arrays.equals(apdu, apduExp)) {
                    log(methodName, printData("apdu   ", apdu));
                    log(methodName, printData("apduExp", apduExp));
                    Log.e(TAG, "apdu does not match the expected value, aborted");
                    return false;
                } else {
                    log(methodName, "apdu matches the test vector, ending with TEST SUCCESS");
                    log(methodName, "NO sendData to PICC run, ended");
                    errorCode = RESPONSE_OK.clone();
                    errorCodeReason = "TEST SUCCESS";
                    return true;
                }
            }

            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        return true;
    }

    public List<byte[]> getReadAllFileContents() {
        List<byte[]> contentList = new ArrayList<>();
        //byte[] content = readStandardFileFull(STANDARD_FILE_NUMBER_01, 0, 32);
        byte[] content = readStandardFilePlain(STANDARD_FILE_NUMBER_01, 0, 32);
        contentList.add(content);

        //content  = readStandardFileFull(STANDARD_FILE_NUMBER_02, 0, 256);
        content = readStandardFilePlain(STANDARD_FILE_NUMBER_02, 0, 256);
        contentList.add(content);
        content = readStandardFileFull(STANDARD_FILE_NUMBER_03, 0, 32);
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
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "wrong fileNumber, aborted";
            return null;
        }
        if ((offset < 0) || (length < 0)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "wrong offset or length, aborted";
            return null;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "isoDep is NULL (maybe it is not a NTAG424DNA tag ?), aborted";
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
        if ((fileNumber < 1) || (fileNumber > 3)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "wrong fileNumber, aborted";
            return null;
        }
        if ((offset < 0) || (length < 0)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "wrong offset or length, aborted";
            return null;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "isoDep is NULL (maybe it is not a NTAG424DNA tag ?), aborted";
            return null;
        }
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            errorCode = RESPONSE_FAILURE_MISSING_AUTHENTICATION.clone();
            errorCodeReason = "missing successful authentication with EV2First or EV2NonFirst, aborted";
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
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
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
        log(methodName, "The fullEncryptedData is of length " + fullEncryptedData.length + " that includes 8 bytes for MAC");
        log(methodName, "The encryptedData length is " + encryptedDataLength);
        encryptedData = Arrays.copyOfRange(fullEncryptedData, 0, encryptedDataLength);
        responseMACTruncatedReceived = Arrays.copyOfRange(fullEncryptedData, encryptedDataLength, fullEncryptedData.length);
        log(methodName, printData("encryptedData", encryptedData));

        // start decrypting the data
        byte[] commandCounterLsb2 =
                intTo2ByteArrayInversed(CmdCounter);
        byte[] padding = hexStringToByteArray("0000000000000000");
        byte[] startingIv = new byte[16];
        ByteArrayOutputStream decryptBaos = new ByteArrayOutputStream();
        decryptBaos.write(HEADER_ENC, 0, HEADER_ENC.length);
        decryptBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        decryptBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        decryptBaos.write(padding, 0, padding.length);
        byte[] ivInputResponse = decryptBaos.toByteArray();
        log(methodName, printData("ivInputResponse", ivInputResponse));
        byte[] ivResponse = AES.encrypt(startingIv, SesAuthENCKey, ivInputResponse);
        log(methodName, printData("ivResponse", ivResponse));
        byte[] decryptedData = AES.decrypt(ivResponse, SesAuthENCKey, encryptedData);
        log(methodName, printData("decryptedData", decryptedData));
        byte[] readData = Arrays.copyOfRange(decryptedData, 0, length); // todo: if length is 0 (meaning all data) this function returns 0
        // todo: read fileSize or known fileSize from data sheet (32/256/128)
        log(methodName, printData("readData", readData));
        // verifying the received MAC
        if (verifyResponseMac(responseMACTruncatedReceived, encryptedData)) {
            return readData;
        } else {
            return null;
        }
    }

    public boolean writeStandardFilePlain(byte fileNumber, byte[] dataToWrite, int offset, int length) {
        String logData = "";
        final String methodName = "writeStandardFilePlain";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, printData("dataToWrite", dataToWrite));
        
        // sanity checks
        if ((fileNumber < (byte) 0x01) || (fileNumber > (byte) 0x03)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "fileNumber is not in range 1..3, aborted";
            return false;
        }
        if ((dataToWrite == null) || (dataToWrite.length < 1)) {
            Log.e(TAG, methodName + " dataToWrite is NULL or of length 0, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "dataToWrite is NULL or of length 0, aborted";
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "lost connection to the card, aborted";
            return false;
        }
        // generate the parameter
        byte[] offsetBytes = Utils.intTo3ByteArrayInversed(offset); // LSB order
        byte[] lengthBytes = Utils.intTo3ByteArrayInversed(length); // LSB order
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(offsetBytes, 0, offsetBytes.length);
        baos.write(lengthBytes, 0, lengthBytes.length);
        baos.write(dataToWrite, 0, dataToWrite.length);
        byte[] parameter = baos.toByteArray();
        Log.d(TAG, methodName + printData(" parameter", parameter));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(WRITE_STANDARD_FILE_SECURE_COMMAND, parameter);
            // sample:  903d00002700000000200000323032332e30372e32312031373a30343a30342031323334353637383930313200 (45 bytes)
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            return false;
        }
    }

    /**
     * writes data to a Standard file in CommunicationMode.Full
     * Important: you need a preceding authenticateEv2First call using the read&write or write access key rights
     * and successful authenticate
     * @param fileNumber
     * @param dataToWrite
     * @param offset
     * @param length
     * @param testMode on 'true' there is no transmission but only compairing step results with 
     *                 NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf
     * @return true on success
     */

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
        final String methodName = "writeStandardFileFull";
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
        if ((fileNumber < (byte) 0x01) || (fileNumber > (byte) 0x03)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "fileNumber is not in range 1..3, aborted";
            return false;
        }
        if ((dataToWrite == null) || (dataToWrite.length < 1)) {
            Log.e(TAG, methodName + " dataToWrite is NULL or of length 0, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "dataToWrite is NULL or of length 0, aborted";
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "lost connection to the card, aborted";
            return false;
        }
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            errorCode = RESPONSE_FAILURE_MISSING_AUTHENTICATION.clone();
            errorCodeReason = "missing successful authentication with EV2First or EV2NonFirst, aborted";
            return false;
        }

        // step 8
        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        // MAC_Input
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
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
                response = sendData(apdu);
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
            Log.d(TAG, methodName + " SUCCESS, now verifying the received MAC");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        // verifying the received Response MAC
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            errorCodeReason = "SUCCESS";
            return true;
        } else {
            errorCodeReason = "FAILURE (see errorCode)";
            return false;
        }
    }

    /**
     * add the padding bytes to data that is written to a Standard, Backup, Linear Record or Cyclic Record file
     * The encryption method does need a byte array of multiples of 16 bytes
     * If the unpaddedData is of (multiple) length of 16 the complete padding is added
     *
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

    /**
     * section for key handling
     * @return
     */


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
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyNumber is < 0, aborted";
            return -1;
        }
        if (keyNumber > 4) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyNumber is > 4, aborted";
            return -1;
        }
        
        if ((isoDep == null) || (!isoDep.isConnected())) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "isoDep is NULL (maybe it is not a NTAG424DNA tag ?), aborted";
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

    public boolean changeApplicationKey(byte keyNumber, byte[] keyNew, byte[] keyOld, byte keyVersionNew) {

        // see NTAG 424 DNA NT4H2421Gx.pdf pages 62 - 63
        // see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 40 - 42
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 76 - 80
        // this is based on the key change of an application key on a DESFire Light card
        // Cmd.ChangeKey is always run in CommunicationMode.Full and there are 2 use cases:
        // Case 1: Key number to be changed ≠ Key number for currently authenticated session
        // Case 2: Key number to be changed == Key number for currently authenticated session (usually the application Master key)

        // todo work on case 2

        String logData = "";
        final String methodName = "changeApplicationKey";
        log(methodName, "started", true);
        log(methodName, "keyNumber: " + keyNumber);
        log(methodName, printData("keyNew", keyNew));
        log(methodName, printData("keyOld", keyOld));
        log(methodName, "keyVersionNew: " + keyVersionNew);
        // sanity checks
        errorCode = new byte[2];
        // sanity checks
        if (keyNumber < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyNumber is < 0, aborted";
            return false;
        }
        if (keyNumber > 4) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyNumber is > 4, aborted";
            return false;
        }
        if ((keyNew == null) || (keyNew.length != 16)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyNew length is not 16, aborted";
            return false;
        }
        if ((keyOld == null) || (keyOld.length != 16)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyOld length is not 16, aborted";
            return false;
        }
        if (keyVersionNew < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyVersionNew is < 0, aborted";
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "isoDep is NULL (maybe it is not a NTAG424DNA tag ?), aborted";
            return false;
        }
/*
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }

 */

        // Encrypting the Command Data
        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        byte[] commandCounterLsb = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb", commandCounterLsb));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(HEADER_MAC, 0, HEADER_MAC.length);
        baosIvInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosIvInput.write(commandCounterLsb, 0, commandCounterLsb.length);
        baosIvInput.write(padding1, 0, padding1.length);
        byte[] ivInput = baosIvInput.toByteArray();
        log(methodName, printData("ivInput", ivInput));

        // IV for CmdData = Enc(KSesAuthENC, IV_Input)
        log(methodName, printData("SesAuthENCKey", SesAuthENCKey));
        byte[] startingIv = new byte[16];
        byte[] ivForCmdData = AES.encrypt(startingIv, SesAuthENCKey, ivInput);
        log(methodName, printData("ivForCmdData", ivForCmdData));

        // Data (New KeyValue || New KeyVersion || CRC32 of New KeyValue || Padding)
        // 0123456789012345678901234567890100A0A608688000000000000000000000
        // 01234567890123456789012345678901 00 A0A60868 8000000000000000000000
        // keyNew 16 byte              keyVers crc32 4  padding 11 bytes

        // error: this is missing in DESFire Light Feature & Hints
        // see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 71
        // 'if key 1 to 4 are to be changed (NewKey XOR OldKey) || KeyVer || CRC32NK'
        // if the keyNumber of the key to change is not the keyNumber that authenticated
        // we need to xor the new key with the old key, the CRC32 is run over the real new key (not the  XORed one)
        byte[] keyNewXor = keyNew.clone();
        for (int i = 0; i < keyOld.length; i++) {
            keyNewXor[i] ^= keyOld[i % keyOld.length];
        }
        log(methodName, printData("keyNewXor", keyNewXor));
        byte[] crc32 = CRC32.get(keyNew);
        log(methodName, printData("crc32 of keyNew", crc32));
        byte[] padding = hexStringToByteArray("8000000000000000000000");
        ByteArrayOutputStream baosData = new ByteArrayOutputStream();
        baosData.write(keyNewXor, 0, keyNewXor.length);
        baosData.write(keyVersionNew);
        baosData.write(crc32, 0, crc32.length);
        baosData.write(padding, 0, padding.length);
        byte[] data = baosData.toByteArray();
        log(methodName, printData("data", data));

        // Encrypt the Command Data = E(KSesAuthENC, Data)
        byte[] encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, data);
        log(methodName, printData("encryptedData", encryptedData));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader = keyNumber || Encrypted CmdData )
        // C40000BC354CD50180D40DB52D5D8CA136249A0A14154DBA1BE0D67C408AB24CF0F3D3B4FE333C6A
        // C4 0000 BC354CD5 01 80D40DB52D5D8CA136249A0A14154DBA1BE0D67C408AB24CF0F3D3B4FE333C6A
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(CHANGE_KEY_SECURE_COMMAND); // 0xC4
        baosMacInput.write(commandCounterLsb, 0, commandCounterLsb.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(keyNumber);
        baosMacInput.write(encryptedData, 0, encryptedData.length);
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));

        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // Data (CmdHeader = keyNumber || Encrypted Data || MAC)
        ByteArrayOutputStream baosChangeKeyCommand = new ByteArrayOutputStream();
        baosChangeKeyCommand.write(keyNumber);
        baosChangeKeyCommand.write(encryptedData, 0, encryptedData.length);
        baosChangeKeyCommand.write(macTruncated, 0, macTruncated.length);
        byte[] changeKeyCommand = baosChangeKeyCommand.toByteArray();
        log(methodName, printData("changeKeyCommand", changeKeyCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(CHANGE_KEY_SECURE_COMMAND, changeKeyCommand);
            log(methodName, printData("apdu", apdu));
            response = isoDep.transceive(apdu);
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

        // compare the responseMAC's
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            errorCodeReason = "SUCCESS";
            return true;
        } else {
            errorCodeReason = "FAILURE (see errorCode)";
            return false;
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
     *
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
            log(methodName, "rndA is NULL or wrong length, aborted");
            return null;
        }
        if ((rndB == null) || (rndB.length != 16)) {
            log(methodName, "rndB is NULL or wrong length, aborted");
            return null;
        }
        if ((authenticationKey == null) || (authenticationKey.length != 16)) {
            log(methodName, "authenticationKey is NULL or wrong length, aborted");
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
        byte[] counter = new byte[]{(byte) (0x00), (byte) (0x01)}; // fixed to 0x0001
        byte[] length = new byte[]{(byte) (0x00), (byte) (0x80)}; // fixed to 0x0080

        System.arraycopy(HEADER_MAC, 0, cmacInput, 0, 2);
        System.arraycopy(counter, 0, cmacInput, 2, 2);
        System.arraycopy(length, 0, cmacInput, 4, 2);
        System.arraycopy(rndA, 0, cmacInput, 6, 2);

        byte[] rndA02to07 = new byte[6];
        byte[] rndB00to05 = new byte[6];
        rndA02to07 = Arrays.copyOfRange(rndA, 2, 8);
        log(methodName, printData("rndA     ", rndA));
        log(methodName, printData("rndA02to07", rndA02to07));
        rndB00to05 = Arrays.copyOfRange(rndB, 0, 6);
        log(methodName, printData("rndB     ", rndB));
        log(methodName, printData("rndB00to05", rndB00to05));
        byte[] xored = xor(rndA02to07, rndB00to05);
        log(methodName, printData("xored     ", xored));
        System.arraycopy(xored, 0, cmacInput, 8, 6);
        System.arraycopy(rndB, 6, cmacInput, 14, 10);
        System.arraycopy(rndA, 8, cmacInput, 24, 8);

        log(methodName, printData("rndA     ", rndA));
        log(methodName, printData("rndB     ", rndB));
        log(methodName, printData("cmacInput", cmacInput));
        if (TEST_MODE) {
            boolean testResult = compareTestModeValues(cmacInput, sv1_expected, "SV1");
        }
        byte[] iv = new byte[16];
        log(methodName, printData("iv       ", iv));
        byte[] cmac = calculateDiverseKey(authenticationKey, cmacInput);
        log(methodName, printData("cmacOut ", cmac));
        if (TEST_MODE) {
            boolean testResult = compareTestModeValues(cmac, SesAuthENCKey_expected, "SesAUthENCKey");
        }
        return cmac;
    }

    public byte[] getSesAuthEncKeyDesfire(byte[] rndA, byte[] rndB, byte[] authenticationKey) {
        // see
        // see MIFARE DESFire Light contactless application IC pdf, page 28
        final String methodName = "getSesAuthEncKey";
        log(methodName, printData("rndA", rndA) + printData(" rndB", rndB) + printData(" authenticationKey", authenticationKey));
        // sanity checks
        if ((rndA == null) || (rndA.length != 16)) {
            log(methodName, "rndA is NULL or wrong length, aborted");
            return null;
        }
        if ((rndB == null) || (rndB.length != 16)) {
            log(methodName, "rndB is NULL or wrong length, aborted");
            return null;
        }
        if ((authenticationKey == null) || (authenticationKey.length != 16)) {
            log(methodName, "authenticationKey is NULL or wrong length, aborted");
            return null;
        }

        // see Mifare DESFire Light Features and Hints AN12343.pdf page 35
        byte[] cmacInput = new byte[32];
        byte[] counter = new byte[]{(byte) (0x00), (byte) (0x01)}; // fixed to 0x0001
        byte[] length = new byte[]{(byte) (0x00), (byte) (0x80)}; // fixed to 0x0080

        System.arraycopy(HEADER_MAC, 0, cmacInput, 0, 2);
        System.arraycopy(counter, 0, cmacInput, 2, 2);
        System.arraycopy(length, 0, cmacInput, 4, 2);
        System.arraycopy(rndA, 0, cmacInput, 6, 2);

        byte[] rndA02to07 = new byte[6];
        byte[] rndB00to05 = new byte[6];
        rndA02to07 = Arrays.copyOfRange(rndA, 2, 8);
        log(methodName, printData("rndA     ", rndA));
        log(methodName, printData("rndA02to07", rndA02to07));
        rndB00to05 = Arrays.copyOfRange(rndB, 0, 6);
        log(methodName, printData("rndB     ", rndB));
        log(methodName, printData("rndB00to05", rndB00to05));
        byte[] xored = xor(rndA02to07, rndB00to05);
        log(methodName, printData("xored     ", xored));
        System.arraycopy(xored, 0, cmacInput, 8, 6);
        System.arraycopy(rndB, 6, cmacInput, 14, 10);
        System.arraycopy(rndA, 8, cmacInput, 24, 8);

        log(methodName, printData("rndA     ", rndA));
        log(methodName, printData("rndB     ", rndB));
        log(methodName, printData("cmacInput", cmacInput));
        byte[] iv = new byte[16];
        log(methodName, printData("iv       ", iv));
        byte[] cmac = calculateDiverseKey(authenticationKey, cmacInput);
        log(methodName, printData("cmacOut ", cmac));
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
        log(methodName, printData("rndA", rndA) + printData(" rndB", rndB) + printData(" authenticationKey", authenticationKey));
        // sanity checks
        if ((rndA == null) || (rndA.length != 16)) {
            log(methodName, "rndA is NULL or wrong length, aborted");
            return null;
        }
        if ((rndB == null) || (rndB.length != 16)) {
            log(methodName, "rndB is NULL or wrong length, aborted");
            return null;
        }
        if ((authenticationKey == null) || (authenticationKey.length != 16)) {
            log(methodName, "authenticationKey is NULL or wrong length, aborted");
            return null;
        }
        // see Mifare DESFire Light Features and Hints AN12343.pdf page 35
        byte[] cmacInput = new byte[32];
        byte[] counter = new byte[]{(byte) (0x00), (byte) (0x01)}; // fixed to 0x0001
        byte[] length = new byte[]{(byte) (0x00), (byte) (0x80)}; // fixed to 0x0080

        System.arraycopy(HEADER_ENC, 0, cmacInput, 0, 2);
        System.arraycopy(counter, 0, cmacInput, 2, 2);
        System.arraycopy(length, 0, cmacInput, 4, 2);
        System.arraycopy(rndA, 0, cmacInput, 6, 2);

        byte[] rndA02to07 = new byte[6];
        byte[] rndB00to05 = new byte[6];
        rndA02to07 = Arrays.copyOfRange(rndA, 2, 8);
        log(methodName, printData("rndA     ", rndA));
        log(methodName, printData("rndA02to07", rndA02to07));
        rndB00to05 = Arrays.copyOfRange(rndB, 0, 6);
        log(methodName, printData("rndB     ", rndB));
        log(methodName, printData("rndB00to05", rndB00to05));
        byte[] xored = xor(rndA02to07, rndB00to05);
        log(methodName, printData("xored     ", xored));
        System.arraycopy(xored, 0, cmacInput, 8, 6);
        System.arraycopy(rndB, 6, cmacInput, 14, 10);
        System.arraycopy(rndA, 8, cmacInput, 24, 8);

        log(methodName, printData("rndA     ", rndA));
        log(methodName, printData("rndB     ", rndB));
        log(methodName, printData("cmacInput", cmacInput));
        byte[] iv = new byte[16];
        log(methodName, printData("iv       ", iv));
        byte[] cmac = calculateDiverseKey(authenticationKey, cmacInput);
        log(methodName, printData("cmacOut ", cmac));
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

    /**
     * verifies the responseMAC against the responseData using the SesAuthMACKey
     * @param responseMAC
     * @param responseData (if data is encrypted use the encrypted data, not the decrypted data)
     *                     Note: in case of enciphered writings the data is null
     * @return true if MAC equals the calculated MAC
     */

    private boolean verifyResponseMac(byte[] responseMAC, byte[] responseData) {
        final String methodName = "verifyResponseMac";
        byte[] commandCounterLsb = intTo2ByteArrayInversed(CmdCounter);
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb, 0, commandCounterLsb.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        if (responseData != null) {
            responseMacBaos.write(responseData, 0, responseData.length);
        }
        byte[] macInput = responseMacBaos.toByteArray();
        log(methodName, printData("macInput", macInput));
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("responseMACTruncatedReceived  ", responseMAC));
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMAC)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return false;
        }
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
        if (data == null) return false;
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

    private boolean checkAuthenticateAesEv2() {
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            log("checkAuthenticateAesEv2", "issing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            errorCodeReason = "missing successful authentication with EV2First or EV2NonFirst, aborted";
            return false;
        }
        return true;
    }

    private boolean checkIsoDep() {
        if ((isoDep == null) || (!isoDep.isConnected())) {
            log("checkIsoDep", "lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            errorCodeReason = "lost connection to the card";
            return false;
        }
        return true;
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
     *
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
     *
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
        } catch (TagLostException e) {
            errorCodeReason = "TagLostException: " + e.getMessage();
            Log.e(TAG, e.getMessage());
            e.printStackTrace();
            return null;
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
     * The methods tries to reset all settings to factory settings. It is necessary to provide all
     * (changed) keys
     * @param applicationKeys : is a byte[][] of length 5 containing the applicationKeys 0..4 applied to the tag
     * @return true on success
     */

    public boolean resetToFactorySettings(byte[][] applicationKeys) {
        logData = "";
        invalidateAllDataNonFirst();
        final String methodName = "resetToFactorySettings";
        log(methodName, "started", true);
        if (applicationKeys == null) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "applicationKeys are NULL, aborted";
            return false;
        }
        if (applicationKeys.length != 5) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "number of applicationKeys is not 5, aborted";
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "isoDep is NULL (maybe it is not a NTAG424DNA tag ?), aborted";
            return false;
        }

        final byte[] file01_content = hexStringToByteArray("001720010000ff0406e104010000000506e10500808283000000000000000000");
        final byte[] file02_content = new byte[256];
        final byte[] file03_content = new byte[128];
        final byte[] file01_fileSettings = hexStringToByteArray("000000e0200000");
        final byte[] file02_fileSettings = hexStringToByteArray("0000e0ee000100");
        final byte[] file03_fileSettings = hexStringToByteArray("00033023800000");
        final byte defaultKeyVersion = (byte) 0x00; // valid for all 5 application keys
        final byte[] defaultApplicationKey = new byte[16]; // valid for all 5 application keys

/*
fileNumber: 01
fileType: 0 (Standard)
communicationSettings: 00 (Plain)
accessRights RW | CAR: 00
accessRights R  | W:   E0
accessRights RW:       0
accessRights CAR:      0
accessRights R:        14
accessRights W:        0
fileSize: 32
--------------
fileNumber: 02
fileType: 0 (Standard)
communicationSettings: 00 (Plain)
accessRights RW | CAR: E0
accessRights R  | W:   EE
accessRights RW:       14
accessRights CAR:      0
accessRights R:        14
accessRights W:        14
fileSize: 256
--------------
fileNumber: 03
fileType: 0 (Standard)
communicationSettings: 03 (Encrypted)
accessRights RW | CAR: 30
accessRights R  | W:   23
accessRights RW:       3
accessRights CAR:      0
accessRights R:        2
accessRights W:        3
fileSize: 128
         */

        boolean success;
        boolean[] successes = new boolean[20]; // takes all success values
        /*
        successes 00 .. 04: test authenticate with application keys
        successes 05
         */

        // before running any change or write tasks I'm checking that all applicationKeys are valid using authenticateEv2First
        boolean authenticateSuccess = true;
        for (int i = 0; i < 5; i++) {
            success = authenticateAesEv2First((byte) (i & 0x0F), applicationKeys[i]);
            successes[i] = success;
            if (!success) authenticateSuccess = false; // triggers the overall authenticate result
        }
        if (!authenticateSuccess) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "One or more application keys are NOT valid, aborted";
            return false;
        }

        // change application Master key to default with keyVersion 0x00
        //success = changeApplicationKey();

        // change application keys 1..4 to default with keyVersion 0x00

        // change fileSettings for files 1..3 to default

        // write factory content to files
        success = writeStandardFilePlain(STANDARD_FILE_NUMBER_01, file01_content, 0, file01_content.length);
        success = writeStandardFilePlain(STANDARD_FILE_NUMBER_02, file02_content, 0, file02_content.length);
        success = writeStandardFileFull(STANDARD_FILE_NUMBER_01, file03_content, 0, file03_content.length, false);

        return false;
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
