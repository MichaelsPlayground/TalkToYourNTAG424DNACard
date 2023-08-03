package de.androidcrypto.talktoyourntag424dnacard;

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
import java.util.Arrays;

/**
 * This class is taking all methods to work with NXP NTAG 424 DNA tag
 */

/*
This is the complete command set per NTAG 424 DNA NT4H2421Gx.pdf datasheet
                                                                 Impl.
Instruction                       CLA INS Communication mode     Status

IsoSelectApplication               00  A4 CommMode.Plain         implemented
AuthenticateEV2First - Part1       90  71 N/A (command specific)
AuthenticateEV2First - Part2       90  AF
AuthenticateEV2NonFirst - Part1    90  77 N/A (command specific)
AuthenticateEV2NonFirst - Part2    90  AF
AuthenticateLRPFirst - Part1       90  71 N/A (command specific)
AuthenticateLRPFirst - Part2       90  AF
AuthenticateLRPNonFirst - Part1    90  77 N/A (command specific)
AuthenticateLRPNonFirst - Part2    90  AF
ChangeFileSettings                 90  5F CommMode.Full
ChangeKey                          90  C4 CommMode.Full
GetCardUID                         90  51 CommMode.Full
GetFileCounters                    90  F6
GetFileSettings                    90  F5
GetKeyVersion                      90  64
GetVersion - Part1                 90  60 CommMode.Plain         implemented
GetVersion - Part2                 90  AF CommMode.Plain         implemented
GetVersion - Part3                 90  AF CommMode.Plain         implemented
ISOReadBinary                      00  B0
ReadData                           90  AD
Read_Sig                           90  3C
ISOSelectFile                      00  A4
SetConfiguration                   90  5C
ISOUpdateBinary                    00  D6
WriteData                          90  8D
 */

public class Ntag424DnaMethods {

    private static final String TAG = Ntag424DnaMethods.class.getName();
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
     * constants
     */

    private static final byte GET_VERSION_INFO_COMMAND = (byte) 0x60;
    private static final byte GET_ADDITIONAL_FRAME_COMMAND = (byte) 0xAF;
    private static final byte SELECT_APPLICATION_ISO_COMMAND = (byte) 0xA4;
    private static final byte GET_FILE_SETTINGS_COMMAND = (byte) 0xF5;

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
    private static final byte[] RESPONSE_FAILURE = new byte[]{(byte) 0x91, (byte) 0xFF}; // general, undefined failure

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
        log(methodName, Utils.printData("dfApplicationName", dfApplicationName));
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
        fileSettings[0] = new FileSettings(STANDARD_FILE_NUMBER_01_CC, getFileSettings(STANDARD_FILE_NUMBER_01_CC));
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
            throw new RuntimeException(e);
        }
        if (checkResponse(response)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            isApplicationSelected = true;
            return getData(response);
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return null;
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
        Log.d(TAG, Utils.printData("uid", uid));
        writeToUiAppend(textView, Utils.printData("UID", uid));
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
        Log.d(TAG, methodName + " command: " + Utils.byteToHex(command) + Utils.printData(" parameters", parameters));
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
        log(methodName, Utils.printData("send apdu -->", apdu));
        byte[] recvBuffer;
        try {
            recvBuffer = isoDep.transceive(apdu);
        } catch (IOException e) {
            errorCodeReason = "IOException: " + e.getMessage();
            Log.e(TAG, e.getMessage());
            e.printStackTrace();
            return null;
        }
        log(methodName, Utils.printData("received  <--", recvBuffer));
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

    public byte[] getNTAG_424_DNA_DF_APPLICATION_NAME() {
        return NTAG_424_DNA_DF_APPLICATION_NAME;
    }
}
