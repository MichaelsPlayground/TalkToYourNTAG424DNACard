package de.androidcrypto.talktoyourntag424dnacard;

import static de.androidcrypto.talktoyourntag424dnacard.Utils.byteArrayLength4InversedToInt;
import static de.androidcrypto.talktoyourntag424dnacard.Utils.byteToHex;
import static de.androidcrypto.talktoyourntag424dnacard.Utils.bytesToHexNpeUpperCase;
import static de.androidcrypto.talktoyourntag424dnacard.Utils.bytesToHexNpeUpperCaseBlank;
import static de.androidcrypto.talktoyourntag424dnacard.Utils.hexStringToByteArray;
import static de.androidcrypto.talktoyourntag424dnacard.Utils.printData;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.net.Uri;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.text.TextUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.RadioButton;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.google.android.material.textfield.TextInputLayout;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private static final String TAG = MainActivity.class.getName();

    private com.google.android.material.textfield.TextInputEditText output, errorCode;
    private com.google.android.material.textfield.TextInputLayout errorCodeLayout;


    //private FileSettings selectedFileSettings;

    /**
     * section for application handling
     */

    private com.google.android.material.textfield.TextInputEditText numberOfKeys, applicationId, applicationSelected;
    private Button applicationList, applicationCreate, applicationSelect;

    // experimental:

    private byte[] selectedApplicationId = null;
    private Button applicationCreateAes;
    /**
     * section for files
     */

    private Button fileList, fileSelect, getFileSettings, changeFileSettings;
    private com.google.android.material.textfield.TextInputEditText fileSelected;
    private String selectedFileId = "";
    private int selectedFileSize;
    private FileSettings selectedFileSettings;

    /**
     * section for EV2 authentication and communication
     */

    private Button selectApplicationEv2, getAllFileIdsEv2, getAllFileSettingsEv2, completeFileSettingsEv2;

    private Button authD0AEv2, authD2AEv2, authD3AEv2, authD3ACEv2;
    private Button getCardUidEv2, getFileSettingsEv2;
    private Button fileStandardCreateEv2, fileStandardWriteEv2, fileStandardReadEv2;
    private Button fileBackupCreateEv2, fileBackupWriteEv2, fileBackupReadEv2;
    private Button fileValueCreditEv2, fileValueDebitEv2, fileValueReadEv2;
    private Button fileValueSetConfigurationEv2, fileValueDeleteEv2;
    private Button fileRecordCreateEv2, fileRecordWriteEv2, fileRecordReadEv2;
    //private Button fileCreateEv2;

    private Button fileCreateFileSetPlain, fileCreateFileSetMaced, fileCreateFileSetEnciphered;

    private Button changeKeyD3AtoD3AC, changeKeyD3ACtoD3A;
    private Button enableTransactionTimerEv2;


    private Button fileTransactionMacCreateEv2, fileTransactionMacDeleteEv2;
    private Button completeTransactionMacFileEv2;

    /**
     * section for SDM tasks
     */

    private Button createNdefFile256Ev2, sdmChangeFileSettingsEv2, sdmTestFileSettingsEv2;
    private Button sdmGetFileSettingsEv2, sdmDecryptNdefManualEv2;

    /**
     * section for standard file handling
     */

    private Button fileStandardCreate, fileStandardWrite, fileStandardRead;
    private com.google.android.material.textfield.TextInputEditText fileStandardFileId, fileStandardSize, fileStandardData;
    RadioButton rbFileFreeAccess, rbFileKeySecuredAccess;

    /**
     * section for authentication
     */

    private Button authDM0D, authD0D, authD1D, authD2D, authD3D, authD4D; // auth with default DES keys
    private Button authDM0DC, authD0DC, authD1DC, authD2DC, authD3DC, authD4DC; // auth with changed DES keys

    private byte KEY_NUMBER_USED_FOR_AUTHENTICATION; // the key number used for a successful authentication
    private byte[] SESSION_KEY_DES; // filled in authenticate, simply the first (leftmost) 8 bytes of SESSION_KEY_TDES
    private byte[] SESSION_KEY_AES; // filled in authenticate
    private byte[] SESSION_KEY_TDES; // filled in authenticate
    private byte[] IV; // gets updated on each new operation

    // var used by EV2 auth
    private byte[] SES_AUTH_ENC_KEY; // filled in by authenticateEv2
    private byte[] SES_AUTH_MAC_KEY; // filled in by authenticateEv2
    private byte[] TRANSACTION_IDENTIFIER; // filled in by authenticateEv2
    private int CMD_COUNTER; // filled in by authenticateEv2, LSB encoded when in byte[

    /**
     * section for general
     */

    private Button getCardUidDes, getCardUidAes; // get cardUID * encrypted
    private Button getTagVersion, formatPicc;
    private Button getKeyVersion;

    /**
     * section for visualizing DES authentication
     */

    private Button selectApplicationDesVisualizing, authDesVisualizing, readDesVisualizing, writeDesVisualizing;
    private Button changeKeyDes00ToChangedDesVisualizing, changeKeyDes00ToDefaultDesVisualizing;
    private Button changeKeyDes01ToChangedDesVisualizing, changeKeyDes01ToDefaultDesVisualizing, authDesVisualizingC;
    private Button changeKeyDes01ToChanged2DesVisualizing, changeKeyDes01ToDefault2DesVisualizing, authDesVisualizingC2;

    /**
     * section for constants
     */

    private final byte[] APPLICATION_IDENTIFIER = Utils.hexStringToByteArray("D0D1D2"); // AID 'D0 D1 D2'
    private final byte APPLICATION_NUMBER_OF_KEYS = (byte) 0x05; // maximum 5 keys for secured access
    private final byte APPLICATION_MASTER_KEY_SETTINGS = (byte) 0x0F; // 'amks'
    /**
     * for explanations on Master Key Settings see M075031_desfire.pdf page 35:
     * left '0' = Application master key authentication is necessary to change any key (default)
     * right 'f' = bits 3..0
     * bit 3: 1: this configuration is changeable if authenticated with the application master key (default setting)
     * bit 2: 1: CreateFile / DeleteFile is permitted also without application master key authentication (default setting)
     * bit 1: 1: GetFileIDs, GetFileSettings and GetKeySettings commands succeed independently of a preceding application master key authentication (default setting)
     * bit 0: 1: Application master key is changeable (authentication with the current application master key necessary, default setting)
     */

    private final byte FILE_COMMUNICATION_SETTINGS = (byte) 0x00; // plain communication
    /**
     * for explanations on File Communication Settings see M075031_desfire.pdf page 15:
     * byte = 0: Plain communication
     * byte = 1: Plain communication secured by DES/3DES/AES MACing
     * byte = 3: Fully DES/3DES/AES enciphered communication
     */

    private final byte STANDARD_FILE_FREE_ACCESS_ID = (byte) 0x00; // file ID with free access
    private final byte STANDARD_FILE_KEY_SECURED_ACCESS_ID = (byte) 0x01; // file ID with key secured access
    // settings for key secured access depend on RadioButtons rbFileFreeAccess, rbFileKeySecuredAccess
    // key 0 is the  Application Master Key
    private final byte ACCESS_RIGHTS_RW_CAR_FREE = (byte) 0xEE; // Read&Write Access (free) & ChangeAccessRights (free)
    private final byte ACCESS_RIGHTS_R_W_FREE = (byte) 0xEE; // Read Access (free) & Write Access (free)
    private final byte ACCESS_RIGHTS_RW_CAR_SECURED = (byte) 0x12; // Read&Write Access (key 01) & ChangeAccessRights (key 02)
    private final byte ACCESS_RIGHTS_R_W_SECURED = (byte) 0x34; // Read Access (key 03) & Write Access (key 04)
    private int MAXIMUM_FILE_SIZE = 32; // do not increase this value to avoid framing !

    /**
     * section for predefined EV2 authentication file numbers
     */

    private final byte STANDARD_FILE_ENCRYPTED_NUMBER = (byte) 0x03;
    private final byte CYCLIC_RECORD_FILE_ENCRYPTED_NUMBER = (byte) 0x05;
    private final byte TRANSACTION_MAC_FILE_NUMBER = (byte) 0x0F;

    /**
     * section for application keys
     */

    private final byte[] APPLICATION_KEY_MASTER_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000"); // default DES key with 8 nulls
    private final byte[] APPLICATION_KEY_MASTER_DES = Utils.hexStringToByteArray("D000000000000000");
    private final byte[] APPLICATION_KEY_MASTER_AES_DEFAULT = Utils.hexStringToByteArray("00000000000000000000000000000000"); // default AES key with 16 nulls
    private final byte[] APPLICATION_KEY_MASTER_AES = Utils.hexStringToByteArray("A08899AABBCCDD223344556677889911");
    private final byte APPLICATION_KEY_MASTER_NUMBER = (byte) 0x00;

    private final byte[] APPLICATION_KEY_RW_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000"); // default DES key with 8 nulls
    private final byte[] APPLICATION_KEY_RW_DES = Utils.hexStringToByteArray("D10023456789ABCD");
    private final byte[] APPLICATION_KEY_RW_DES_2 = Utils.hexStringToByteArray("D100445566778899");
    private final byte[] APPLICATION_KEY_RW_AES_DEFAULT = Utils.hexStringToByteArray("00000000000000000000000000000000"); // default AES key with 16 nulls
    private final byte APPLICATION_KEY_RW_NUMBER = (byte) 0x03; // changed to DESFIRE
    private final byte[] APPLICATION_KEY_CAR_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000"); // default DES key with 8 nulls
    private final byte[] APPLICATION_KEY_CAR_DES = Utils.hexStringToByteArray("D2100000000000000");
    private final byte[] APPLICATION_KEY_CAR_AES_DEFAULT = Utils.hexStringToByteArray("00000000000000000000000000000000"); // default AES key with 16 nulls
    private final byte[] APPLICATION_KEY_CAR_AES = Utils.hexStringToByteArray("A2000000000000000000000000000000");
    private final byte APPLICATION_KEY_CAR_NUMBER = (byte) 0x00;
    private final byte[] APPLICATION_KEY_R_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000"); // default DES key with 8 nulls
    private final byte[] APPLICATION_KEY_R_DES = Utils.hexStringToByteArray("D3100000000000000");
    private final byte[] APPLICATION_KEY_R_AES_DEFAULT = Utils.hexStringToByteArray("00000000000000000000000000000000"); // default AES key with 16 nulls
    private final byte[] APPLICATION_KEY_R_AES = Utils.hexStringToByteArray("A3000000000000000000000000000000");
    private final byte APPLICATION_KEY_R_NUMBER = (byte) 0x02;
    private final byte[] APPLICATION_KEY_W_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000"); // default DES key with 8 nulls
    private final byte[] APPLICATION_KEY_W_DES = Utils.hexStringToByteArray("D4100000000000000");

    private final byte APPLICATION_KEY_W_NUMBER = (byte) 0x04;

    // see Mifare DESFire Light Features and Hints AN12343.pdf, page 83-84
    private final byte[] TRANSACTION_MAC_KEY_AES = Utils.hexStringToByteArray("F7D23E0C44AFADE542BFDF2DC5C6AE02"); // taken from Mifare DESFire Light Features and Hints AN12343.pdf, pages 83-84

    /**
     * section for commands and responses
     */

    private final byte CREATE_APPLICATION_COMMAND = (byte) 0xCA;
    private final byte SELECT_APPLICATION_COMMAND = (byte) 0x5A;
    private final byte CREATE_STANDARD_FILE_COMMAND = (byte) 0xCD;
    private final byte READ_STANDARD_FILE_COMMAND = (byte) 0xBD;
    private final byte WRITE_STANDARD_FILE_COMMAND = (byte) 0x3D;
    private final byte GET_FILE_SETTINGS_COMMAND = (byte) 0xF5;
    private final byte CHANGE_FILE_SETTINGS_COMMAND = (byte) 0x5F;
    private final byte CHANGE_KEY_COMMAND = (byte) 0xC4;


    private final byte MORE_DATA_COMMAND = (byte) 0xAF;

    private final byte APPLICATION_CRYPTO_DES = 0x00; // add this to number of keys for DES
    private final byte APPLICATION_CRYPTO_AES = (byte) 0x80; // add this to number of keys for AES

    private final byte GET_CARD_UID_COMMAND = (byte) 0x51;
    private final byte GET_VERSION_COMMAND = (byte) 0x60;

    private final byte[] RESPONSE_OK = new byte[]{(byte) 0x91, (byte) 0x00};
    private final byte[] RESPONSE_AUTHENTICATION_ERROR = new byte[]{(byte) 0x91, (byte) 0xAE};
    private final byte[] RESPONSE_MORE_DATA_AVAILABLE = new byte[]{(byte) 0x91, (byte) 0xAF};
    private final byte[] RESPONSE_FAILURE = new byte[]{(byte) 0x91, (byte) 0xFF};

    /**
     * general constants
     */

    int COLOR_GREEN = Color.rgb(0, 255, 0);
    int COLOR_RED = Color.rgb(255, 0, 0);
    private final String outputDivider = "--------------";

    // variables for NFC handling

    private NfcAdapter mNfcAdapter;
    //private CommunicationAdapter adapter;
    private IsoDep isoDep;
    private byte[] tagIdByte;

    private String exportString = "Desfire Authenticate Legacy"; // takes the log data for export
    private String exportStringFileName = "auth.html"; // takes the log data for export


    // DesfireAuthentication is used for all authentication tasks. The constructor needs the isoDep object so it is initialized in 'onTagDiscovered'
    DesfireAuthenticate desfireAuthenticate;

    // DesfireAuthenticationProximity is used for old DES d40 authenticate tasks. The constructor needs the isoDep object so it is initialized in 'onTagDiscovered'
    //DesfireAuthenticateProximity desfireAuthenticateProximity;
    DesfireAuthenticateLegacy desfireAuthenticateLegacy;
    DesfireAuthenticateEv2 desfireAuthenticateEv2;

    private Activity activity;
    private Ntag424DnaMethods ntag424DnaMethods;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etOutput);
        errorCode = findViewById(R.id.etErrorCode);
        errorCodeLayout = findViewById(R.id.etErrorCodeLayout);

        // application handling
        applicationCreate = findViewById(R.id.btnCreateApplication);
        applicationSelect = findViewById(R.id.btnSelectApplication);
        applicationSelected = findViewById(R.id.etSelectedApplicationId);
        numberOfKeys = findViewById(R.id.etNumberOfKeys);
        applicationId = findViewById(R.id.etApplicationId);

        // experimental:
        applicationCreateAes = findViewById(R.id.btnCreateApplicationAes);


        // file handling

        fileList = findViewById(R.id.btnListFiles); // this is misused for getSesAuthEncKey
        fileSelect = findViewById(R.id.btnSelectFile);
        getFileSettings = findViewById(R.id.btnGetFileSettings);
        changeFileSettings = findViewById(R.id.btnChangeFileSettings);
        fileSelected = findViewById(R.id.etSelectedFileId);
        rbFileFreeAccess = findViewById(R.id.rbFileAccessTypeFreeAccess);
        rbFileKeySecuredAccess = findViewById(R.id.rbFileAccessTypeKeySecuredAccess);

        // section for EV2 auth & communication

        selectApplicationEv2 = findViewById(R.id.btnSelectApplicationEv2);
        getAllFileIdsEv2 = findViewById(R.id.btnGetAllFileIdsEv2);
        getAllFileSettingsEv2 = findViewById(R.id.btnGetAllFileSettingsEv2);
        completeFileSettingsEv2 = findViewById(R.id.btnCompleteFileSettingsEv2); // run all 3 commands above

        authD0AEv2 = findViewById(R.id.btnAuthD0AEv2);
        authD2AEv2 = findViewById(R.id.btnAuthD2AEv2);
        authD3AEv2 = findViewById(R.id.btnAuthD3AEv2);
        authD3ACEv2 = findViewById(R.id.btnAuthD3ACEv2);
        getCardUidEv2 = findViewById(R.id.btnGetCardUidEv2);
        getFileSettingsEv2 = findViewById(R.id.btnGetFileSettingsEv2);

        // methods for sdm
        createNdefFile256Ev2 = findViewById(R.id.btnCreateNdef256);
        sdmChangeFileSettingsEv2 = findViewById(R.id.btnSdmChangeFileSettings);
        sdmTestFileSettingsEv2 = findViewById(R.id.btnSdmTestFileSettings);
        sdmGetFileSettingsEv2 = findViewById(R.id.btnSdmGetFileSettingsEv2);
        sdmDecryptNdefManualEv2 = findViewById(R.id.btnSdmDecryptNdefManualEv2);

        //fileCreateEv2 = findViewById(R.id.btnCreateFilesEv2);

        fileStandardCreateEv2 = findViewById(R.id.btnCreateStandardFileEv2);
        fileStandardReadEv2 = findViewById(R.id.btnReadStandardFileEv2);
        fileStandardWriteEv2 = findViewById(R.id.btnWriteStandardFileEv2);

        fileBackupCreateEv2 = findViewById(R.id.btnCreateBackupFileEv2);
        fileBackupReadEv2 = findViewById(R.id.btnReadBackupFileEv2);
        fileBackupWriteEv2 = findViewById(R.id.btnWriteBackupFileEv2);

        fileValueCreditEv2 = findViewById(R.id.btnCreditValueFileEv2);
        fileValueDebitEv2 = findViewById(R.id.btnDebitValueFileEv2);
        fileValueReadEv2 = findViewById(R.id.btnReadValueFileEv2);
        fileValueSetConfigurationEv2 = findViewById(R.id.btnSetConfigurationValueFileEv2);
        fileValueDeleteEv2 = findViewById(R.id.btnDeleteValueFileEv2);

        fileRecordCreateEv2 = findViewById(R.id.btnCreateRecordFileEv2);
        fileRecordReadEv2 = findViewById(R.id.btnReadRecordFileEv2);
        fileRecordWriteEv2 = findViewById(R.id.btnWriteRecordFileEv2);

        fileCreateFileSetEnciphered = findViewById(R.id.btnCreateFileSetEncipheredEv2);

        fileTransactionMacCreateEv2 = findViewById(R.id.btnCreateTransactionMacFileEv2);
        fileTransactionMacDeleteEv2 = findViewById(R.id.btnDeleteTransactionMacFileEv2);
        completeTransactionMacFileEv2 = findViewById(R.id.btnCompleteTransactionMacFileEv2);


        changeKeyD3AtoD3AC = findViewById(R.id.btnChangeKeyD3AtoD3ACEv2); // change AES key 03 from DEFAULT to CHANGED
        changeKeyD3ACtoD3A = findViewById(R.id.btnChangeKeyD3ACtoD3AEv2); // change AES key 03 from CHANGED to DEFAULT
        enableTransactionTimerEv2 = findViewById(R.id.btnEnableTransactionTimerEv2);

        // standard files
        fileStandardCreate = findViewById(R.id.btnCreateStandardFile);
        fileStandardRead = findViewById(R.id.btnReadStandardFile);
        fileStandardWrite = findViewById(R.id.btnWriteStandardFile);
        fileStandardFileId = findViewById(R.id.etFileStandardFileId);
        fileStandardSize = findViewById(R.id.etFileStandardSize);
        fileStandardData = findViewById(R.id.etFileStandardData);

        // authentication handling DES default keys
        authDM0D = findViewById(R.id.btnAuthDM0D);
        authD0D = findViewById(R.id.btnAuthD0D);
        authD1D = findViewById(R.id.btnAuthD1D);
        authD2D = findViewById(R.id.btnAuthD2D);
        authD3D = findViewById(R.id.btnAuthD3D);
        authD4D = findViewById(R.id.btnAuthD4D);
        // authentication handling DES changed keys
        authD0DC = findViewById(R.id.btnAuthD0DC);
        authD1DC = findViewById(R.id.btnAuthD1DC);
        authD2DC = findViewById(R.id.btnAuthD2DC);
        authD3DC = findViewById(R.id.btnAuthD3DC);
        authD4DC = findViewById(R.id.btnAuthD4DC);

        // general handling
        getCardUidDes = findViewById(R.id.btnGetCardUidDes);
        getCardUidAes = findViewById(R.id.btnGetCardUidAes);
        getTagVersion = findViewById(R.id.btnGetTagVersion);
        formatPicc = findViewById(R.id.btnFormatPicc);
        getKeyVersion = findViewById(R.id.btnGetKeyVersion);

        // visualize DES authentication
        selectApplicationDesVisualizing = findViewById(R.id.btnDesVisualizeAuthSelect);
        authDesVisualizing = findViewById(R.id.btnDesVisualizeAuthAuthenticate);
        authDesVisualizingC = findViewById(R.id.btnDesVisualizeAuthAuthenticateC);
        authDesVisualizingC2 = findViewById(R.id.btnDesVisualizeAuthAuthenticateC2);
        readDesVisualizing = findViewById(R.id.btnDesVisualizeAuthRead);
        writeDesVisualizing = findViewById(R.id.btnDesVisualizeAuthWrite);
        changeKeyDes00ToChangedDesVisualizing = findViewById(R.id.btnDesVisualizeChangeKeyDes00ToChanged);
        changeKeyDes00ToDefaultDesVisualizing = findViewById(R.id.btnDesVisualizeChangeKeyDes00ToDefault);
        changeKeyDes01ToChangedDesVisualizing = findViewById(R.id.btnDesVisualizeChangeKeyDes01ToChanged);
        changeKeyDes01ToDefaultDesVisualizing = findViewById(R.id.btnDesVisualizeChangeKeyDes01ToDefault);
        // this is for changing the CHANGED key to CHANGED 2 key and from CHANGED 2 key to DEFAULT key
        changeKeyDes01ToChanged2DesVisualizing = findViewById(R.id.btnDesVisualizeChangeKeyDes01ToChanged2);
        changeKeyDes01ToDefault2DesVisualizing = findViewById(R.id.btnDesVisualizeChangeKeyDes01ToDefault2);


        // some presets
        applicationId.setText(Utils.bytesToHexNpeUpperCase(APPLICATION_IDENTIFIER));
        numberOfKeys.setText(String.valueOf((int) APPLICATION_NUMBER_OF_KEYS));
        fileStandardFileId.setText(String.valueOf((int) STANDARD_FILE_FREE_ACCESS_ID)); // preset is FREE ACCESS

        activity = MainActivity.this;

        /**
         * just es quick test button
         */
        Button pad = findViewById(R.id.btncardUIDxx);
        pad.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                byte[] fileSettings02 = desfireAuthenticateEv2.getFileSettingsEv2((byte) 0x02);
                Log.d(TAG, printData("fileSettings02", fileSettings02));

                byte[] fileSettings05 = desfireAuthenticateEv2.getFileSettingsEv2((byte) 0x05);
                Log.d(TAG, printData("fileSettings05", fileSettings05));

                byte[] fileSettings08 = desfireAuthenticateEv2.getFileSettingsEv2((byte) 0x08);
                Log.d(TAG, printData("fileSettings08", fileSettings08));

                byte[] fileSettings11 = desfireAuthenticateEv2.getFileSettingsEv2((byte) 0x0b);
                Log.d(TAG, printData("fileSettings11", fileSettings11));

                byte[] fileSettings14 = desfireAuthenticateEv2.getFileSettingsEv2((byte) 0x0e);
                Log.d(TAG, printData("fileSettings14", fileSettings14));
            }
        });

        rbFileFreeAccess.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean b) {
                if (b) {
                    // free access
                    fileStandardFileId.setText(String.valueOf((int) STANDARD_FILE_FREE_ACCESS_ID));
                } else {
                    // key secured access
                    fileStandardFileId.setText(String.valueOf((int) STANDARD_FILE_KEY_SECURED_ACCESS_ID));
                }
            }
        });

        // hide soft keyboard from showing up on startup
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        /**
         * section for application handling
         */

        applicationCreate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "create a new application";
                writeToUiAppend(output, logString);
                byte numberOfKeysByte = Byte.parseByte(numberOfKeys.getText().toString());
                byte[] applicationIdentifier = Utils.hexStringToByteArray(applicationId.getText().toString());
                if (applicationIdentifier == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you entered a wrong application ID", COLOR_RED);
                    return;
                }
                //Utils.reverseByteArrayInPlace(applicationIdentifier); // change to LSB = change the order
                if (applicationIdentifier.length != 3) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you did not enter a 6 hex string application ID", COLOR_RED);
                    return;
                }
                writeToUiAppend(output, logString + " with id: " + applicationId.getText().toString());
                byte[] responseData = new byte[2];
                boolean success = createApplicationPlainCommunicationDes(output, applicationIdentifier, numberOfKeysByte, responseData);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        // experimental
        applicationCreateAes.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "create a new AES application";
                writeToUiAppend(output, logString);
                byte numberOfKeysByte = Byte.parseByte(numberOfKeys.getText().toString());
                byte[] applicationIdentifier = Utils.hexStringToByteArray(applicationId.getText().toString());
                if (applicationIdentifier == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you entered a wrong application ID", COLOR_RED);
                    return;
                }
                //Utils.reverseByteArrayInPlace(applicationIdentifier); // change to LSB = change the order
                if (applicationIdentifier.length != 3) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you did not enter a 6 hex string application ID", COLOR_RED);
                    return;
                }
                writeToUiAppend(output, logString + " with id: " + applicationId.getText().toString());
                byte[] responseData = new byte[2];
                boolean success = createApplicationPlainCommunicationAes(output, applicationIdentifier, numberOfKeysByte, responseData);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        applicationSelect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "select a NDEF application ISO";
                writeToUiAppend(output, logString);

                boolean success = ntag424DnaMethods.selectNdefApplicationIso();
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    selectedApplicationId = ntag424DnaMethods.getNTAG_424_DNA_DF_APPLICATION_NAME().clone();
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                }
            }
        });

        /**
         * section for EV2 authentication and communication
         */

        /**
         * section for application handling using authenticateEv2 class
         */

        selectApplicationEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "select an application EV2";
                writeToUiAppend(output, logString);
                byte[] applicationIdentifier = Utils.hexStringToByteArray(applicationId.getText().toString());
                if (applicationIdentifier == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you entered a wrong application ID", COLOR_RED);
                    return;
                }
                //Utils.reverseByteArrayInPlace(applicationIdentifier); // change to LSB = change the order
                if (applicationIdentifier.length != 3) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you did not enter a 6 hex string application ID", COLOR_RED);
                    return;
                }
                writeToUiAppend(output, logString + " with id: " + applicationId.getText().toString());
                byte[] responseData = new byte[2];
                boolean success = desfireAuthenticateEv2.selectApplicationByAidEv2(applicationIdentifier);
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (success) {
                    selectedApplicationId = applicationIdentifier.clone();
                    applicationSelected.setText(bytesToHexNpeUpperCase(selectedApplicationId));
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    selectedApplicationId = null;
                    applicationSelected.setText("please select an application");
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        getAllFileIdsEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "get all file IDs from a selected application EV2";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }

                byte[] responseData = new byte[2];
                byte[] result = desfireAuthenticateEv2.getAllFileIdsEv2();
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (result != null) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppend(output, "found these fileIDs (not sorted): " + bytesToHexNpeUpperCaseBlank(result));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Depending on the Application Master Keys settings a previous authentication with the Application Master Key is required");
                }
            }
        });

        getAllFileSettingsEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "get all file settings from a selected application EV2";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }

                byte[] responseData = new byte[2];
                FileSettings[] result = desfireAuthenticateEv2.getAllFileSettingsEv2();
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (result != null) {
                    int numberOfFfileSettings = result.length;
                    for (int i = 0; i < numberOfFfileSettings; i++) {
                        // first check that this entry is not null
                        FileSettings fileSettings = result[i];
                        if (fileSettings != null) {
                            writeToUiAppend(output, fileSettings.dump());
                        }
                    }
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Depending on the Application Master Keys settings a previous authentication with the Application Master Key is required");
                }
            }
        });

        completeFileSettingsEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "complete file settings (AIO) EV2";
                writeToUiAppend(output, logString);

                // this is the combined command for select, fileIds and allFileSettings
                byte[] applicationIdentifier = Utils.hexStringToByteArray(applicationId.getText().toString());
                if (applicationIdentifier == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you entered a wrong application ID", COLOR_RED);
                    return;
                }
                //Utils.reverseByteArrayInPlace(applicationIdentifier); // change to LSB = change the order
                if (applicationIdentifier.length != 3) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you did not enter a 6 hex string application ID", COLOR_RED);
                    return;
                }
                writeToUiAppend(output, logString + " with id: " + applicationId.getText().toString());
                byte[] responseData = new byte[2];
                boolean success = desfireAuthenticateEv2.selectApplicationByAidEv2(applicationIdentifier);
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (success) {
                    selectedApplicationId = applicationIdentifier.clone();
                    applicationSelected.setText(bytesToHexNpeUpperCase(selectedApplicationId));
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    selectedApplicationId = null;
                    applicationSelected.setText("please select an application");
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }

                byte[] result = desfireAuthenticateEv2.getAllFileIdsEv2();
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (result != null) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppend(output, "found these fileIDs (not sorted): " + bytesToHexNpeUpperCaseBlank(result));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Depending on the Application Master Keys settings a previous authentication with the Application Master Key is required");
                }

                FileSettings[] fsResult = desfireAuthenticateEv2.getAllFileSettingsEv2();
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (result != null) {
                    int numberOfFfileSettings = result.length;
                    for (int i = 0; i < numberOfFfileSettings; i++) {
                        // first check that this entry is not null
                        FileSettings fileSettings = fsResult[i];
                        if (fileSettings != null) {
                            writeToUiAppend(output, fileSettings.dump());
                        }
                    }
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Depending on the Application Master Keys settings a previous authentication with the Application Master Key is required");
                }
            }
        });


        /**
         * section for authentication using authenticationEv2First
         */

        authD0AEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read access key = 03...
                clearOutputFields();
                String logString = "EV2 First authenticate with DEFAULT AES key number 0x00 = application master key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }

                // run a self test
                //boolean getSesAuthKeyTestResult = desfireAuthenticateEv2.getSesAuthKeyTest();
                //writeToUiAppend(output, "getSesAuthKeyTestResult: " + getSesAuthKeyTestResult);

                exportString = "";
                exportStringFileName = "auth.html";

                byte[] responseData = new byte[2];
                boolean success = ntag424DnaMethods.authenticateAesEv2First(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_AES_DEFAULT);
                responseData = ntag424DnaMethods.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SES_AUTH_ENC_KEY = ntag424DnaMethods.getSesAuthENCKey();
                    SES_AUTH_MAC_KEY = ntag424DnaMethods.getSesAuthMACKey();
                    TRANSACTION_IDENTIFIER = ntag424DnaMethods.getTransactionIdentifier();
                    CMD_COUNTER = ntag424DnaMethods.getCmdCounter();
                    writeToUiAppend(output, printData("SES_AUTH_ENC_KEY", SES_AUTH_ENC_KEY));
                    writeToUiAppend(output, printData("SES_AUTH_MAC_KEY", SES_AUTH_MAC_KEY));
                    writeToUiAppend(output, printData("TRANSACTION_IDENTIFIER", TRANSACTION_IDENTIFIER));
                    writeToUiAppend(output, "CMD_COUNTER: " + CMD_COUNTER);
                    writeToUiAppend(output, "key used for auth: " + ntag424DnaMethods.getKeyNumberUsedForAuthentication());
                    vibrateShort();
                    // show logData

                    // prepare data for export
                    exportString = ntag424DnaMethods.getLogData();
                    exportStringFileName = "auth0a_ev2.html";
                    writeToUiToast("your authentication log file is ready for export");

                    //showDialog(MainActivity.this, desfireAuthenticateProximity.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        authD2AEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read access key = 02...
                clearOutputFields();
                String logString = "EV2 First authenticate with DEFAULT AES key number 0x02 = read access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }

                byte[] responseData = new byte[2];
                boolean success = ntag424DnaMethods.authenticateAesEv2First(APPLICATION_KEY_R_NUMBER, APPLICATION_KEY_R_AES_DEFAULT);
                responseData = ntag424DnaMethods.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SES_AUTH_ENC_KEY = ntag424DnaMethods.getSesAuthENCKey();
                    SES_AUTH_MAC_KEY = ntag424DnaMethods.getSesAuthMACKey();
                    TRANSACTION_IDENTIFIER = ntag424DnaMethods.getTransactionIdentifier();
                    CMD_COUNTER = ntag424DnaMethods.getCmdCounter();
                    writeToUiAppend(output, printData("SES_AUTH_ENC_KEY", SES_AUTH_ENC_KEY));
                    writeToUiAppend(output, printData("SES_AUTH_MAC_KEY", SES_AUTH_MAC_KEY));
                    writeToUiAppend(output, printData("TRANSACTION_IDENTIFIER", TRANSACTION_IDENTIFIER));
                    writeToUiAppend(output, "CMD_COUNTER: " + CMD_COUNTER);
                    writeToUiAppend(output, "key used for auth: " + ntag424DnaMethods.getKeyNumberUsedForAuthentication());
                    vibrateShort();
                    // show logData

                    // prepare data for export
                    exportString = ntag424DnaMethods.getLogData();
                    exportStringFileName = "auth2a_ev2.html";
                    writeToUiToast("your authentication log file is ready for export");

                    //showDialog(MainActivity.this, desfireAuthenticateProximity.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        authD3AEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read access key = 03...
                clearOutputFields();
                String logString = "EV2 First authenticate with DEFAULT AES key number 0x03 = read & write access rights key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }

                // run a self test
                //boolean getSesAuthKeyTestResult = ntag424DnaMethods.getSesAuthKeyTest();
                //writeToUiAppend(output, "getSesAuthKeyTestResult: " + getSesAuthKeyTestResult);

                byte[] responseData = new byte[2];
                boolean success = ntag424DnaMethods.authenticateAesEv2First(APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_AES_DEFAULT);
                responseData = ntag424DnaMethods.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SES_AUTH_ENC_KEY = ntag424DnaMethods.getSesAuthENCKey();
                    SES_AUTH_MAC_KEY = ntag424DnaMethods.getSesAuthMACKey();
                    TRANSACTION_IDENTIFIER = ntag424DnaMethods.getTransactionIdentifier();
                    CMD_COUNTER = ntag424DnaMethods.getCmdCounter();
                    writeToUiAppend(output, printData("SES_AUTH_ENC_KEY", SES_AUTH_ENC_KEY));
                    writeToUiAppend(output, printData("SES_AUTH_MAC_KEY", SES_AUTH_MAC_KEY));
                    writeToUiAppend(output, printData("TRANSACTION_IDENTIFIER", TRANSACTION_IDENTIFIER));
                    writeToUiAppend(output, "CMD_COUNTER: " + CMD_COUNTER);
                    writeToUiAppend(output, "key used for auth: " + ntag424DnaMethods.getKeyNumberUsedForAuthentication());
                    vibrateShort();
                    // show logData

                    // prepare data for export
                    exportString = ntag424DnaMethods.getLogData();
                    exportStringFileName = "auth2a_ev2.html";
                    writeToUiToast("your authentication log file is ready for export");

                    //showDialog(MainActivity.this, desfireAuthenticateProximity.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        authD3ACEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read access key = 03...
                clearOutputFields();
                String logString = "EV2 First authenticate with CHANGED AES key number 0x03 = read access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }

                // run a self test
                //boolean getSesAuthKeyTestResult = desfireAuthenticateEv2.getSesAuthKeyTest();
                //writeToUiAppend(output, "getSesAuthKeyTestResult: " + getSesAuthKeyTestResult);

                byte[] responseData = new byte[2];
                boolean success = desfireAuthenticateEv2.authenticateAesEv2First(APPLICATION_KEY_R_NUMBER, APPLICATION_KEY_R_AES);
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SES_AUTH_ENC_KEY = desfireAuthenticateEv2.getSesAuthENCKey();
                    SES_AUTH_MAC_KEY = desfireAuthenticateEv2.getSesAuthMACKey();
                    TRANSACTION_IDENTIFIER = desfireAuthenticateEv2.getTransactionIdentifier();
                    CMD_COUNTER = desfireAuthenticateEv2.getCmdCounter();
                    writeToUiAppend(output, printData("SES_AUTH_ENC_KEY", SES_AUTH_ENC_KEY));
                    writeToUiAppend(output, printData("SES_AUTH_MAC_KEY", SES_AUTH_MAC_KEY));
                    writeToUiAppend(output, printData("TRANSACTION_IDENTIFIER", TRANSACTION_IDENTIFIER));
                    writeToUiAppend(output, "CMD_COUNTER: " + CMD_COUNTER);
                    vibrateShort();
                    // show logData

                    // prepare data for export
                    exportString = desfireAuthenticateEv2.getLogData();
                    exportStringFileName = "auth3ac_ev2.html";
                    writeToUiToast("your authentication log file is ready for export");

                    //showDialog(MainActivity.this, desfireAuthenticateProximity.getLogData());
                } else {
                    writeToUiAppend(output, logString + " FAILURE");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        getCardUidEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "getCardUidEv2";
                writeToUiAppend(output, logString);

                // just for testing - test the macOverCommand value
                boolean macOverCommandTestResult = desfireAuthenticateEv2.macOverCommandTest();
                writeToUiAppend(output, "macOverCommandTestResult: " + macOverCommandTestResult);
                // just for testing - test the truncateMAC
                boolean truncateMACTestResult = desfireAuthenticateEv2.truncateMACTest();
                writeToUiAppend(output, "truncateMACTestResult: " + truncateMACTestResult);
                // just for testing - test the decryptData
                boolean decryptDataTestResult = desfireAuthenticateEv2.decryptDataTest();
                writeToUiAppend(output, "decryptDataTestResult: " + decryptDataTestResult);
                byte[] cardUidReceived = desfireAuthenticateEv2.getCardUidEv2();
                writeToUiAppend(output, printData("cardUidReceived", cardUidReceived));
            }
        });

        getFileSettingsEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "getFileSettingsEv2";
                writeToUiAppend(output, logString);
                writeToUiAppend(output, "Reading the file settings for predefined files");


                // just for testing - test the macOverCommand value
                //boolean macOverCommandTestResult = desfireAuthenticateEv2.macOverCommandTest();
                //writeToUiAppend(output, "macOverCommandTestResult: " + macOverCommandTestResult);
                // just for testing - test the truncateMAC
                //boolean truncateMACTestResult = desfireAuthenticateEv2.truncateMACTest();
                //writeToUiAppend(output, "truncateMACTestResult: " + truncateMACTestResult);
                // just for testing - test the decryptData
                //boolean decryptDataTestResult = desfireAuthenticateEv2.decryptDataTest();
                //writeToUiAppend(output, "decryptDataTestResult: " + decryptDataTestResult);


                byte fileNumberByte = STANDARD_FILE_ENCRYPTED_NUMBER;
                byte[] fileSettingsReceived = desfireAuthenticateEv2.getFileSettingsEv2(fileNumberByte);
                if (fileSettingsReceived != null) {
                    FileSettings fileSettingsStandardEncryptedFile = new FileSettings(fileNumberByte, fileSettingsReceived);
                    writeToUiAppend(output, "read file settings:\n" + fileSettingsStandardEncryptedFile.dump());
                } else {
                    writeToUiAppend(output, "no file settings available (file not existed ?) for fileId: " + fileNumberByte);
                }

                fileNumberByte = CYCLIC_RECORD_FILE_ENCRYPTED_NUMBER;
                fileSettingsReceived = desfireAuthenticateEv2.getFileSettingsEv2(fileNumberByte);
                if (fileSettingsReceived != null) {
                    FileSettings fileSettingsCyclicRecordEncryptedFile = new FileSettings(fileNumberByte, fileSettingsReceived);
                    writeToUiAppend(output, "read file settings:\n" + fileSettingsCyclicRecordEncryptedFile.dump());
                } else {
                    writeToUiAppend(output, "no file settings available (file not existed ?) for fileId: " + fileNumberByte);
                }
            }
        });

        /*
        fileCreateEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "create a set of files EV2";
                writeToUiAppend(output, logString);
                writeToUiAppend(output, "Note: using a FIXED fileNumber 2 and fileSize of 32 for this method");

                int fileSizeInt = 32; // fixed
                // check that an application was selected before
                if (selectedApplicationId == null) {
                    writeToUiAppend(output, "You need to select an application first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }

                byte fileIdByte = (byte) 0x08; // fixed for Value file encrypted

                writeToUiAppend(output, logString + " with id: " + fileIdByte);
                byte[] responseData = new byte[2];
                // create a Standard file with Encrypted communication
                boolean success = desfireAuthenticateEv2.createAFile(fileIdByte, DesfireAuthenticateEv2.DesfireFileType.Value, DesfireAuthenticateEv2.CommunicationSettings.Encrypted);
                responseData = desfireAuthenticateEv2.getErrorCode();
                //boolean success = createStandardFilePlainCommunicationDes(output, fileIdByte, fileSizeInt, rbFileFreeAccess.isChecked(), responseData);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });
*/


        /**
         * section for Standard files
         */

        fileStandardCreateEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "create a new standard file EV2";
                writeToUiAppend(output, logString);
                writeToUiAppend(output, "Note: using a FIXED fileNumber 2 and fileSize of 32 for this method");
                byte fileIdByte = (byte) 0x02; // fixed
                int fileSizeInt = 32; // fixed
                // check that an application was selected before
                if (selectedApplicationId == null) {
                    writeToUiAppend(output, "You need to select an application first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                writeToUiAppend(output, logString + " with id: " + fileIdByte + " size: " + fileSizeInt);
                byte[] responseData = new byte[2];
                // create a Standard file with Encrypted communication
                boolean success = desfireAuthenticateEv2.createStandardFileEv2(fileIdByte, fileSizeInt, true, true);
                responseData = desfireAuthenticateEv2.getErrorCode();
                //boolean success = createStandardFilePlainCommunicationDes(output, fileIdByte, fileSizeInt, rbFileFreeAccess.isChecked(), responseData);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        fileStandardReadEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "read from a standard file EV2";
                writeToUiAppend(output, logString);
                // todo skipped, using a fixed fileNumber
                selectedFileId = "2";
                fileSelected.setText(selectedFileId);

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                //byte fileIdByte = Byte.parseByte(selectedFileId);

                // just for testing - test the macOverCommand value
                //boolean readDataFullPart1TestResult = desfireAuthenticateEv2.readDataFullPart1Test();
                //writeToUiAppend(output, "readDataFullPart1TestResult: " + readDataFullPart1TestResult);

                byte fileIdByte = desfireAuthenticateEv2.STANDARD_FILE_ENCRYPTED_NUMBER; //byte) 0x02; // fixed

                byte[] responseData = new byte[2];
                //byte[] result = readFromAStandardFilePlainCommunicationDes(output, fileIdByte, selectedFileSize, responseData);
                byte[] result = desfireAuthenticateEv2.readStandardFileEv2(fileIdByte);
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (result == null) {
                    // something gone wrong
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkResponseMoreData(responseData)) {
                        writeToUiAppend(output, "the file is too long to read, sorry");
                    }
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a READ ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                } else {
                    writeToUiAppend(output, logString + " ID: " + fileIdByte + printData(" data", result));
                    writeToUiAppend(output, logString + " ID: " + fileIdByte + " data: " + new String(result, StandardCharsets.UTF_8));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                }
            }
        });

        fileStandardWriteEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "write to a standard file EV2";
                writeToUiAppend(output, logString);

                // todo skipped, using a fixed fileNumber
                selectedFileId = String.valueOf(desfireAuthenticateEv2.STANDARD_FILE_ENCRYPTED_NUMBER); // 2
                fileSelected.setText(selectedFileId);
                int SELECTED_FILE_SIZE_FIXED = 32;

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }

                // we are going to write a timestamp to the file
                String dataToWrite = Utils.getTimestamp();

                //dataToWrite = "123 some data";

                if (TextUtils.isEmpty(dataToWrite)) {
                    //writeToUiAppend(errorCode, "please enter some data to write");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "please enter some data to write", COLOR_RED);
                    return;
                }

                // just for testing - test the macOverCommand value
                //boolean writeDataFullPart1TestResult = desfireAuthenticateEv2.writeDataFullPart1Test();
                //writeToUiAppend(output, "writeDataFullPart1TestResult: " + writeDataFullPart1TestResult);

                byte[] dataToWriteBytes = dataToWrite.getBytes(StandardCharsets.UTF_8);
                // create an empty array and copy the dataToWrite to clear the complete standard file
                //byte[] fullDataToWrite = new byte[selectedFileSize];
                byte[] fullDataToWrite = new byte[SELECTED_FILE_SIZE_FIXED];
                System.arraycopy(dataToWriteBytes, 0, fullDataToWrite, 0, dataToWriteBytes.length);
                byte fileIdByte = Byte.parseByte(selectedFileId);
                byte[] responseData = new byte[2];
                //boolean success = writeToAStandardFilePlainCommunicationDes(output, fileIdByte, fullDataToWrite, responseData);
                boolean success = desfireAuthenticateEv2.writeStandardFileEv2(fileIdByte, fullDataToWrite);
                //boolean success = false;
                responseData = desfireAuthenticateEv2.getErrorCode();

                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a WRITE ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        /**
         * section for Backup files
         */

        fileBackupCreateEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "create a new Backup file EV2";
                writeToUiAppend(output, logString);
                writeToUiAppend(output, "Note: using a FIXED fileNumber 5 and fileSize of 32 for this method");
                byte fileIdByte = desfireAuthenticateEv2.BACKUP_FILE_ENCRYPTED_NUMBER; // (byte) 0x05; // fixed
                int fileSizeInt = 32; // fixed
                // check that an application was selected before
                if (selectedApplicationId == null) {
                    writeToUiAppend(output, "You need to select an application first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                writeToUiAppend(output, logString + " with id: " + fileIdByte + " size: " + fileSizeInt);
                byte[] responseData = new byte[2];
                // create a Backup file with Encrypted communication

                // not ready so far
                //boolean success = desfireAuthenticateEv2.createBackupFileEv2(fileIdByte, fileSizeInt, true, true);
                boolean success = false;
                responseData = desfireAuthenticateEv2.getErrorCode();
                //boolean success = createBackupFilePlainCommunicationDes(output, fileIdByte, fileSizeInt, rbFileFreeAccess.isChecked(), responseData);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        fileBackupReadEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "read from a Backup file EV2";
                writeToUiAppend(output, logString);
                // todo skipped, using a fixed fileNumber
                selectedFileId = "5";
                fileSelected.setText(selectedFileId);

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                //byte fileIdByte = Byte.parseByte(selectedFileId);

                // just for testing - test the macOverCommand value
                //boolean readDataFullPart1TestResult = desfireAuthenticateEv2.readDataFullPart1Test();
                //writeToUiAppend(output, "readDataFullPart1TestResult: " + readDataFullPart1TestResult);

                byte fileIdByte = desfireAuthenticateEv2.BACKUP_FILE_ENCRYPTED_NUMBER; //byte) 0x05; // fixed

                byte[] responseData = new byte[2];
                //byte[] result = readFromABackupFilePlainCommunicationDes(output, fileIdByte, selectedFileSize, responseData);
                byte[] result = desfireAuthenticateEv2.readDataFileEv2(fileIdByte);
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (result == null) {
                    // something gone wrong
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkResponseMoreData(responseData)) {
                        writeToUiAppend(output, "the file is too long to read, sorry");
                    }
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a READ ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                } else {
                    writeToUiAppend(output, logString + " ID: " + fileIdByte + printData(" data", result));
                    writeToUiAppend(output, logString + " ID: " + fileIdByte + " data: " + new String(result, StandardCharsets.UTF_8));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                }
            }
        });

        fileBackupWriteEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "write to a Backup file EV2";
                writeToUiAppend(output, logString);

                // todo skipped, using a fixed fileNumber
                selectedFileId = String.valueOf(desfireAuthenticateEv2.BACKUP_FILE_ENCRYPTED_NUMBER); // 5
                fileSelected.setText(selectedFileId);
                int SELECTED_FILE_SIZE_FIXED = 32;

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }

                // we are going to write a timestamp to the file
                String dataToWrite = Utils.getTimestamp();

                //dataToWrite = "123 some data";

                if (TextUtils.isEmpty(dataToWrite)) {
                    //writeToUiAppend(errorCode, "please enter some data to write");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "please enter some data to write", COLOR_RED);
                    return;
                }

                // just for testing - test the macOverCommand value
                //boolean writeDataFullPart1TestResult = desfireAuthenticateEv2.writeDataFullPart1Test();
                //writeToUiAppend(output, "writeDataFullPart1TestResult: " + writeDataFullPart1TestResult);

                byte[] dataToWriteBytes = dataToWrite.getBytes(StandardCharsets.UTF_8);
                // create an empty array and copy the dataToWrite to clear the complete Backup file
                //byte[] fullDataToWrite = new byte[selectedFileSize];
                byte[] fullDataToWrite = new byte[SELECTED_FILE_SIZE_FIXED];
                System.arraycopy(dataToWriteBytes, 0, fullDataToWrite, 0, dataToWriteBytes.length);
                byte fileIdByte = Byte.parseByte(selectedFileId);
                byte[] responseData = new byte[2];
                //boolean success = writeToABackupFilePlainCommunicationDes(output, fileIdByte, fullDataToWrite, responseData);
                boolean success = desfireAuthenticateEv2.writeBackupFileEv2(fileIdByte, fullDataToWrite);
                //boolean success = false;
                responseData = desfireAuthenticateEv2.getErrorCode();

                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    //vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a WRITE ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                }

                boolean successCommit = desfireAuthenticateEv2.commitTransactionEv2();
                responseData = desfireAuthenticateEv2.getErrorCode();
                writeToUiAppend(output, "commitSuccess: " + successCommit);
                if (!successCommit) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit NOT Success, aborted", COLOR_RED);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Did you forget to authenticate with a WRITE ACCESS Key first ?");
                    return;
                }
                writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit SUCCESS", COLOR_GREEN);
                vibrateShort();
            }
        });

        /**
         * section for value files
         */

        fileValueReadEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "get the value from a Value file EV2";
                writeToUiAppend(output, logString);
                // todo skipped, using a fixed fileNumber
                selectedFileId = "8";
                fileSelected.setText(selectedFileId);

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                //byte fileIdByte = Byte.parseByte(selectedFileId);

                byte fileIdByte = (byte) 0x08; // fixed

                byte[] responseData = new byte[2];
                int result = desfireAuthenticateEv2.getValueFileEv2(fileIdByte);
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (result < 0) {
                    // something gone wrong
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a READ ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                } else {
                    writeToUiAppend(output, logString + " ID: " + fileIdByte + " value: " + result);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                }
            }
        });


        fileValueCreditEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "credit the value on a Value file EV2";
                writeToUiAppend(output, logString);
                // todo skipped, using a fixed fileNumber
                selectedFileId = "8";
                fileSelected.setText(selectedFileId);

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                //byte fileIdByte = Byte.parseByte(selectedFileId);

                byte fileIdByte = (byte) 0x08; // fixed

                int changeValue = 7; // fixed
                writeToUiAppend(output, "The value file will get CREDITED by " + changeValue);

                byte[] responseData = new byte[2];
                boolean success = desfireAuthenticateEv2.creditValueFileEv2(fileIdByte, changeValue);
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    //vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a WRITE ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return; // don't submit a commit
                }
                boolean successCommit = desfireAuthenticateEv2.commitTransactionEv2();
                responseData = desfireAuthenticateEv2.getErrorCode();
                writeToUiAppend(output, "commitSuccess: " + successCommit);
                if (!successCommit) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit NOT Success, aborted", COLOR_RED);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Did you forget to authenticate with a WRITE ACCESS Key first ?");
                    return;
                }
                writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit SUCCESS", COLOR_GREEN);
                vibrateShort();

            }
        });

        fileValueDebitEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "debit the value on a Value file EV2";
                writeToUiAppend(output, logString);
                // todo skipped, using a fixed fileNumber
                selectedFileId = "8";
                fileSelected.setText(selectedFileId);

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                //byte fileIdByte = Byte.parseByte(selectedFileId);

                byte fileIdByte = (byte) 0x08; // fixed

                int changeValue = 7; // fixed
                writeToUiAppend(output, "The value file will get DEBITED by " + changeValue);

                byte[] responseData = new byte[2];
                boolean success = desfireAuthenticateEv2.debitValueFileEv2(fileIdByte, changeValue);
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a WRITE ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return; // don't submit a commit
                }
                boolean successCommit = desfireAuthenticateEv2.commitTransactionEv2();
                responseData = desfireAuthenticateEv2.getErrorCode();
                writeToUiAppend(output, "commitSuccess: " + successCommit);
                if (!successCommit) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit NOT Success, aborted", COLOR_RED);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Did you forget to authenticate with a WRITE ACCESS Key first ?");
                    return;
                }
                writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit SUCCESS", COLOR_GREEN);
                vibrateShort();
            }
        });

        fileValueSetConfigurationEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "set the Configuration of a Value file EV2";
                writeToUiAppend(output, logString);
                // todo skipped, using a fixed fileNumber
                selectedFileId = "8";
                fileSelected.setText(selectedFileId);

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                //byte fileIdByte = Byte.parseByte(selectedFileId);

                byte fileIdByte = (byte) 0x08; // fixed

                byte[] responseData = new byte[2];
                boolean success = desfireAuthenticateEv2.setConfigurationValueFileLimit(fileIdByte);
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with the APPLICATION MASTER KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return; // don't submit a commit
                }

            }
        });


        /**
         * section for record files
         */

        fileRecordWriteEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "write to a cyclic record file EV2";
                writeToUiAppend(output, logString);

                // todo skipped, using a fixed fileNumber
                selectedFileId = "14";
                fileSelected.setText(selectedFileId);
                int SELECTED_FILE_SIZE_FIXED = 32;

                int recordSize = 32; // fixed at the moment

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                String dataToWrite = fileStandardData.getText().toString();
                dataToWrite = "123 some data";

                if (TextUtils.isEmpty(dataToWrite)) {
                    //writeToUiAppend(errorCode, "please enter some data to write");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "please enter some data to write", COLOR_RED);
                    return;
                }

                // just for testing - test the macOverCommand value
                //boolean writeDataFullPart1TestResult = desfireAuthenticateEv2.writeDataFullPart1Test();
                //writeToUiAppend(output, "writeDataFullPart1TestResult: " + writeDataFullPart1TestResult);

                // limit the string
                String dataToWriteString = Utils.getTimestamp() + " " + dataToWrite;

                if (dataToWriteString.length() > recordSize)
                    dataToWriteString = dataToWriteString.substring(0, recordSize);
                byte[] dataToWriteStringBytes = dataToWriteString.getBytes(StandardCharsets.UTF_8);
                byte[] fullDataToWrite = new byte[recordSize];
                System.arraycopy(dataToWriteStringBytes, 0, fullDataToWrite, 0, dataToWriteStringBytes.length);
                writeToUiAppend(output, printData("fullDataToWrite", fullDataToWrite));

                // todo this is a hard coded padding to avoid any longer data because when the dataToWrite
                // is a multiple of AES block size (16 bytes) we need to add a new data block for padding
                // here the padding is added on the last 2 bytes of the  record size
                fullDataToWrite[30] = (byte) 0x80;
                fullDataToWrite[31] = (byte) 0x00;
                writeToUiAppend(output, "## removed last 2 bytes of fullDataToWrite and added a padding ##");
                writeToUiAppend(output, printData("fullDataToWrite", fullDataToWrite));

                byte fileIdByte = Byte.parseByte(selectedFileId);
                byte[] responseData = new byte[2];
                boolean success = desfireAuthenticateEv2.writeRecordFileEv2(fileIdByte, fullDataToWrite);
                //boolean success = false;
                responseData = desfireAuthenticateEv2.getErrorCode();

                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a WRITE ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return; // don't submit a commit
                }

                boolean successCommit = desfireAuthenticateEv2.commitTransactionEv2();
                responseData = desfireAuthenticateEv2.getErrorCode();
                writeToUiAppend(output, "commitSuccess: " + successCommit);
                if (!successCommit) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit NOT Success, aborted", COLOR_RED);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Did you forget to authenticate with a WRITE ACCESS Key first ?");
                    return;
                }
                vibrateShort();
                writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit SUCCESS", COLOR_GREEN);
            }
        });

        fileRecordReadEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "read from a cyyclic record file EV2";
                writeToUiAppend(output, logString);
                // todo skipped, using a fixed fileNumber
                selectedFileId = "14";
                fileSelected.setText(selectedFileId);

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                //byte fileIdByte = Byte.parseByte(selectedFileId);

                // just for testing - test the macOverCommand value
                //boolean readDataFullPart1TestResult = desfireAuthenticateEv2.readDataFullPart1Test();
                //writeToUiAppend(output, "readDataFullPart1TestResult: " + readDataFullPart1TestResult);

                byte fileIdByte = (byte) 0x0E; // fixed

                byte[] responseData = new byte[2];
                //byte[] result = readFromAStandardFilePlainCommunicationDes(output, fileIdByte, selectedFileSize, responseData);
                byte[] result = desfireAuthenticateEv2.readRecordFileEv2(fileIdByte);
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (result == null) {
                    // something gone wrong
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkResponseMoreData(responseData)) {
                        writeToUiAppend(output, "the file is too long to read, sorry");
                    }
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a READ ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                } else {
                    writeToUiAppend(output, logString + " ID: " + fileIdByte + printData(" data", result));
                    writeToUiAppend(output, logString + " ID: " + fileIdByte + " data: " + new String(result, StandardCharsets.UTF_8));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                }
            }
        });


        fileTransactionMacCreateEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                // status WORKING

                clearOutputFields();
                String logString = "create a new Transaction MAC file EV2";
                writeToUiAppend(output, logString);
                writeToUiAppend(output, "Note: using a FIXED fileNumber 15 for this method");
                // check that an application was selected before
                if (selectedApplicationId == null) {
                    writeToUiAppend(output, "You need to select an application first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                writeToUiAppend(output, logString + " with id: " + TRANSACTION_MAC_FILE_NUMBER);

                // just for testing - test the macOverCommand value
                boolean createTransactionMacFileFullPart1TestResult = desfireAuthenticateEv2.createTransactionMacFileFullPart1Test();
                writeToUiAppend(output, "createTransactionMacFileFullPart1TestResult: " + createTransactionMacFileFullPart1TestResult);
                if (!createTransactionMacFileFullPart1TestResult) return;

                byte[] responseData = new byte[2];
                // create a Standard file with Encrypted communication
                boolean success = desfireAuthenticateEv2.createTransactionMacFileEv2(TRANSACTION_MAC_FILE_NUMBER, TRANSACTION_MAC_KEY_AES);
                responseData = desfireAuthenticateEv2.getErrorCode();
                //boolean success = createStandardFilePlainCommunicationDes(output, fileIdByte, fileSizeInt, rbFileFreeAccess.isChecked(), responseData);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        fileTransactionMacDeleteEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                // status WORKING

                clearOutputFields();
                String logString = "delete a Transaction MAC file EV2";
                writeToUiAppend(output, logString);
                writeToUiAppend(output, "Note: using a FIXED fileNumber 15 for this method");
                // check that an application was selected before
                if (selectedApplicationId == null) {
                    writeToUiAppend(output, "You need to select an application first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                writeToUiAppend(output, logString + " with id: " + TRANSACTION_MAC_FILE_NUMBER);

                byte[] responseData = new byte[2];
                boolean success = desfireAuthenticateEv2.deleteTransactionMacFileEv2(TRANSACTION_MAC_FILE_NUMBER);
                responseData = desfireAuthenticateEv2.getErrorCode();
                //boolean success = createStandardFilePlainCommunicationDes(output, fileIdByte, fileSizeInt, rbFileFreeAccess.isChecked(), responseData);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        completeTransactionMacFileEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "complete Transaction MAC file EV2";
                writeToUiAppend(output, logString);
                writeToUiAppend(output, "Note: the app will run a complete session using the TMAC file:\n" +
                        "1. write a new record to the enciphered Cyclic Record file (file id 14\n" +
                        "2. commit the transaction with commitTMACTransactionEv2\n" +
                        "3. read the TMAC file content\n\n" +
                        "Note: this will FAIL when no TMAC file is present in application !");

                // check that an application was selected before
                if (selectedApplicationId == null) {
                    writeToUiAppend(output, "You need to select an application first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                writeToUiAppend(output, logString + " with id: " + TRANSACTION_MAC_FILE_NUMBER);

                // step 1: write a new record
                selectedFileId = "14";
                fileSelected.setText(selectedFileId);
                int recordSize = 32; // fixed at the moment

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                String dataToWrite = "123 some data";

                // limit the string
                String dataToWriteString = Utils.getTimestamp() + " " + dataToWrite;
                if (dataToWriteString.length() > recordSize)
                    dataToWriteString = dataToWriteString.substring(0, recordSize);
                byte[] dataToWriteStringBytes = dataToWriteString.getBytes(StandardCharsets.UTF_8);
                byte[] fullDataToWrite = new byte[recordSize];
                System.arraycopy(dataToWriteStringBytes, 0, fullDataToWrite, 0, dataToWriteStringBytes.length);
                writeToUiAppend(output, printData("fullDataToWrite", fullDataToWrite));

                // todo this is a hard coded padding to avoid any longer data because when the dataToWrite
                // is a multiple of AES block size (16 bytes) we need to add a new data block for padding
                // here the padding is added on the last 2 bytes of the  record size
                fullDataToWrite[30] = (byte) 0x80;
                fullDataToWrite[31] = (byte) 0x00;
                writeToUiAppend(output, "## removed last 2 bytes of fullDataToWrite and added a padding ##");
                writeToUiAppend(output, printData("fullDataToWrite", fullDataToWrite));

                byte fileIdByte = Byte.parseByte(selectedFileId);
                byte[] responseData = new byte[2];
                boolean success = desfireAuthenticateEv2.writeRecordFileEv2(fileIdByte, fullDataToWrite);
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a WRITE ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return; // don't submit a commit
                }

                writeToUiAppend(output, "now we are running the commitTMACTransactionEv2");

                boolean successCommit = desfireAuthenticateEv2.commitTMACTransactionEv2();
                responseData = desfireAuthenticateEv2.getErrorCode();
                writeToUiAppend(output, "commitSuccess: " + successCommit);
                if (!successCommit) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit NOT Success, aborted", COLOR_RED);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Did you forget to authenticate with a WRITE ACCESS Key first ?");
                    return;
                }
                vibrateShort();
                writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit SUCCESS", COLOR_GREEN);

                // read the TMAC file content
                //byte fileIdTmacByte = (byte) 0x0F; // fixed

                // as the communication mode is PLAIN we are using the traditional reading method

                responseData = new byte[2];
                byte[] result = readFromAStandardFilePlainCommunication(output, TRANSACTION_MAC_FILE_NUMBER, 12, responseData);
                if (result == null) {
                    // something gone wrong
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkResponseMoreData(responseData)) {
                        writeToUiAppend(output, "the file is too long to read, sorry");
                    }
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a READ ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                } else {
                    writeToUiAppend(output, logString + " ID: " + fileIdByte + printData(" data", result));

                    // split the received data:
                    // should be TMC || TMV
                    // sample: TMC (TMAC Counter) : 04000000 (4 bytes, counter in LSB encoding)
                    // sample: TMV (TMAC Value)   : 94A3205E41588BA9 (8 bytes)
                    // split up the data to TMC and TMV
                    byte[] tmcByte = Arrays.copyOfRange(result, 0, 4);
                    byte[] tmvByte = Arrays.copyOfRange(result, 4, 8);
                    int tmcInt = byteArrayLength4InversedToInt(tmcByte);
                    writeToUiAppend(output, logString + printData(" tmcByte", tmcByte));
                    writeToUiAppend(output, logString + " tmcInt: " + tmcInt);
                    writeToUiAppend(output, logString + printData(" tmvByte", tmvByte));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                }
            }
        });

        /**
         * section  for changing keys
         */

        changeKeyD3AtoD3AC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "change AES application key 03 (READ) from DEFAULT to CHANGED EV2";
                writeToUiAppend(output, logString);
                // check that an application was selected before
                if (selectedApplicationId == null) {
                    writeToUiAppend(output, "You need to select an application first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }

                byte[] responseData = new byte[2];
                boolean success = desfireAuthenticateEv2.changeApplicationKeyEv2(APPLICATION_KEY_R_NUMBER, APPLICATION_KEY_R_AES, APPLICATION_KEY_R_AES_DEFAULT);
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        changeKeyD3ACtoD3A.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "change AES application key 03 (READ) from CHANGED to DEFAULT EV2";
                writeToUiAppend(output, logString);
                // check that an application was selected before
                if (selectedApplicationId == null) {
                    writeToUiAppend(output, "You need to select an application first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }

                byte[] responseData = new byte[2];
                boolean success = desfireAuthenticateEv2.changeApplicationKeyEv2(APPLICATION_KEY_R_NUMBER, APPLICATION_KEY_R_AES_DEFAULT, APPLICATION_KEY_R_AES);
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        enableTransactionTimerEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "enableTransactionTimer EV2";
                writeToUiAppend(output, logString);
                // check that an application was selected before
                if (selectedApplicationId == null) {
                    writeToUiAppend(output, "You need to select an application first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                // this is manual workflow

                // see Feature & Hints, pages 12 - 15, full enciphered !!


                byte[] apdu, response;
                byte SET_CONFIGURATION_COMMAND = (byte) 0x03;
                //byte[] parameterEnabling = new byte[]{(byte) 0x04};
                //byte[] parameterEnabling = new byte[]{(byte) 0x01};
                byte[] parameterEnabling = new byte[]{(byte) 0x01, (byte) 0x01};
                //byte[] parameter = new byte[]{(byte) 0x55};
                byte[] parameter = new byte[]{(byte) 0x55, (byte) 0x01};
                byte[] responseData = new byte[2];
                try {
                    //apdu = wrapMessage(SET_CONFIGURATION_COMMAND, parameter);
                    apdu = wrapMessage(SET_CONFIGURATION_COMMAND, parameterEnabling);
                    Log.d(TAG, logString + printData(" apdu", apdu));
                    response = isoDep.transceive(apdu);
                    Log.d(TAG, logString + printData(" response", response));
                } catch (IOException e) {
                    Log.e(TAG, logString + " transceive failed, IOException:\n" + e.getMessage());
                    writeToUiAppend(output, "transceive failed: " + e.getMessage());
                    System.arraycopy(RESPONSE_FAILURE, 0, responseData, 0, 2);
                    return;
                }
                byte[] responseBytes = returnStatusBytes(response);
                System.arraycopy(responseBytes, 0, responseData, 0, 2);
                if (checkResponse(response)) {
                    Log.d(TAG, logString + " SUCCESS");
                    return;
                } else {
                    Log.d(TAG, logString + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
                    Log.d(TAG, logString + " error code: " + EV3.getErrorCode(responseBytes));
                    return;
                }


                /*
                byte[] responseData = new byte[2];
                boolean success = createStandardFilePlainCommunicationDes(output, fileIdByte, fileSizeInt, rbFileFreeAccess.isChecked(), responseData);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }

                byte[] responseData = new byte[2];
                boolean success = desfireAuthenticateEv2.changeApplicationKeyEv2(APPLICATION_KEY_R_NUMBER, APPLICATION_KEY_R_AES_DEFAULT, APPLICATION_KEY_R_AES);
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }

                 */
            }
        });


        /**
         * section for files and standard files
         */

        // this method is misused for getSesAuthEncKey
        fileList.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "getSesAuthEncKeyMain";
                writeToUiAppend(output, logString);
                byte[] rndA = Utils.hexStringToByteArray("B04D0787C93EE0CC8CACC8E86F16C6FE");
                byte[] rndB = Utils.hexStringToByteArray("FA659AD0DCA738DD65DC7DC38612AD81");
                byte[] key = Utils.hexStringToByteArray("00000000000000000000000000000000");
                // calculate the SesAuthENCKey
                byte[] SesAuthENCKey_expected = Utils.hexStringToByteArray("63DC07286289A7A6C0334CA31C314A04");
                DesfireAuthenticateProximity desfireAuthenticateProximity1 = new DesfireAuthenticateProximity(isoDep, true);
                byte[] SesAuthENCKey = desfireAuthenticateProximity1.getSesAuthEncKey(rndA, rndB, key);
                writeToUiAppend(output, printData("SesAuthENCKey_expected", SesAuthENCKey_expected));
                writeToUiAppend(output, printData("SesAuthENCKey calcultd", SesAuthENCKey));
                // calculate the SesAuthMACKey
                byte[] SesAuthMACKey_expected = Utils.hexStringToByteArray("774F26743ECE6AF5033B6AE8522946F6");
                byte[] SesAuthMACKey = desfireAuthenticateProximity1.getSesAuthMacKey(rndA, rndB, key);
                writeToUiAppend(output, printData("SesAuthMACKey_expected", SesAuthMACKey_expected));
                writeToUiAppend(output, printData("SesAuthMACKey calcultd", SesAuthMACKey));
            }
        });

        fileStandardCreate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "create a new standard file";
                writeToUiAppend(output, logString);
                byte fileIdByte = Byte.parseByte(fileStandardFileId.getText().toString());
                int fileSizeInt = Integer.parseInt(fileStandardSize.getText().toString());
                // check that an application was selected before
                if (selectedApplicationId == null) {
                    writeToUiAppend(output, "You need to select an application first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                writeToUiAppend(output, logString + " with id: " + fileStandardFileId.getText().toString() + " size: " + fileSizeInt);
                byte[] responseData = new byte[2];
                boolean success = createStandardFilePlainCommunicationDes(output, fileIdByte, fileSizeInt, rbFileFreeAccess.isChecked(), responseData);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        fileSelect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "select a file";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppend(output, "You need to select an application first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                // at this point we should read the available file ids from the card
                //byte fileIdByte = Byte.parseByte(fileStandardFileId.getText().toString());
                // as well we should read the file settings of the selected file to know about e.g. the file type and file size
                selectedFileId = fileStandardFileId.getText().toString();
                selectedFileSize = MAXIMUM_FILE_SIZE; // this value should be read from file settings
                fileSelected.setText(fileStandardFileId.getText().toString());
                writeToUiAppend(output, "you selected the fileID " + selectedFileId);
                writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " file selection SUCCESS", COLOR_GREEN);
                vibrateShort();
            }
        });

        fileStandardRead.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "read from all standard files";
                writeToUiAppend(output, logString);

                // check that an application was selected before
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }

                List<byte[]> fileContents = ntag424DnaMethods.getReadAllFileContents();
                if ((fileContents == null) || (fileContents.size() < 1)) {
                    writeToUiAppend(output, logString + " FAILURE");
                    return;
                } else {
                    for (int i = 0; i < fileContents.size(); i++) {
                        writeToUiAppend(output, "fileNumber: " + i + "\n" +
                                Utils.printData("fileContent", fileContents.get(i)));
                        writeToUiAppend(output, outputDivider);
                        vibrateShort();
                    }
                }
            }
        });

        fileStandardWrite.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "write to a standard file";
                writeToUiAppend(output, logString);

                writeToUiAppend(output, "This is using the TEST_MODE");

                boolean successTest = ntag424DnaMethods.writeStandardFileFull((byte) 0x03, "123".getBytes(StandardCharsets.UTF_8), 0, 3, true);
                writeToUiAppend(output, "TEST_MODE result: " + successTest);

                if (!TextUtils.isEmpty(logString)) return;
                // ending TEST

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                String dataToWrite = Utils.getTimestamp() + " 123456789012"; // gives a 32 bytes long string
                //String dataToWrite = fileStandardData.getText().toString();
                if (TextUtils.isEmpty(dataToWrite)) {
                    //writeToUiAppend(errorCode, "please enter some data to write");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "please enter some data to write", COLOR_RED);
                    return;
                }
                byte[] dataToWriteBytes = dataToWrite.getBytes(StandardCharsets.UTF_8);
                // create an empty array and copy the dataToWrite to clear the complete standard file
                byte[] fullDataToWrite = new byte[selectedFileSize];
                System.arraycopy(dataToWriteBytes, 0, fullDataToWrite, 0, dataToWriteBytes.length);
                byte fileIdByte = Byte.parseByte(selectedFileId);
                byte[] responseData = new byte[2];
                boolean success = writeToAStandardFilePlainCommunicationDes(output, fileIdByte, fullDataToWrite, responseData);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a WRITE ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        getFileSettings.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "get all file settings from a selected application";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }

                byte[] responseData = new byte[2];
                //FileSettings[] result = desfireAuthenticateEv2.getAllFileSettingsEv2();
                FileSettings[] result = ntag424DnaMethods.getAllFileSettings();
                responseData = ntag424DnaMethods.getErrorCode();
                if (result != null) {
                    int numberOfFfileSettings = result.length;
                    for (int i = 0; i < numberOfFfileSettings; i++) {
                        // first check that this entry is not null
                        FileSettings fileSettings = result[i];
                        if (fileSettings.getCompleteResponse() != null) {
                            writeToUiAppend(output, fileSettings.dump());
                            writeToUiAppend(output, outputDivider);
                        } else {
                            writeToUiAppend(output, "could not retrieve fileSettings");
                            writeToUiAppend(output, outputDivider);
                        }
                    }
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Depending on the Application Master Keys settings a previous authentication with the Application Master Key is required");
                }
            }
        });

        /*
        getFileSettings.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "get file settings";
                writeToUiAppend(output, logString);
                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte fileIdByte = Byte.parseByte(selectedFileId);
                byte[] responseData = new byte[2];
                byte[] result = desfireAuthenticateLegacy.getFileSettings(fileIdByte);
                responseData = desfireAuthenticateLegacy.getErrorCode();
                if (result == null) {
                    // something gone wrong
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkResponseMoreData(responseData)) {
                        writeToUiAppend(output, "the data I'm receiving is too long to read, sorry");
                    }
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with the Application Master Key ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(output, desfireAuthenticate.getLogData());
                    return;
                } else {
                    writeToUiAppend(output, logString + " ID: " + fileIdByte + printData(" data", result));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    // get the data in the  FileSettings class
                    selectedFileSettings = new FileSettings(fileIdByte, result);
                    writeToUiAppend(output, selectedFileSettings.dump());
                    vibrateShort();
                }
            }
        });

         */

        changeFileSettings.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "change the fileSettings of a file";
                writeToUiAppend(output, logString);
                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte fileIdByte = Byte.parseByte(selectedFileId);
                byte[] responseData = new byte[2];
                boolean success = desfireAuthenticateLegacy.changeFileSettings(fileIdByte);
                responseData = desfireAuthenticateLegacy.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    // NOTE: don't forget to authenticate with CAR key
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Did you forget to authenticate with the CAR key ?");
                }
            }
        });

        /**
         * section for file sets
         */

        fileCreateFileSetEnciphered.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "create a file set (5 files) ENCIPHERED EV2";
                writeToUiAppend(output, logString);
                writeToUiAppend(output, "Note: this will create a set of 5 files (Standard, Backup, Value, Linear Record and Cyclic Record type)");
                // check that an application was selected before
                if (selectedApplicationId == null) {
                    writeToUiAppend(output, "You need to select an application first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // create a file set with Encrypted communication
                boolean success = desfireAuthenticateEv2.createFileSetEncrypted(); // returns true in any case !
                responseData = desfireAuthenticateEv2.getErrorCode();
                //boolean success = createStandardFilePlainCommunicationDes(output, fileIdByte, fileSizeInt, rbFileFreeAccess.isChecked(), responseData);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        /**
         * section for authentication with DEFAULT DES keys
         */

        authD0D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the application master key = 00...
                clearOutputFields();
                String logString = "authenticate with DEFAULT DES key number 0x00 = application master key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];

                // this is the authentication method from the NFCJLIB, working correctly
                boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_DES_DEFAULT);

                if (success) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    writeToUiAppend(output, logString + " SUCCESS");
                    SESSION_KEY_DES = desfireAuthenticate.getSessionKey();
                    vibrateShort();
                    // show logData

                    // prepare data for export
                    exportString = desfireAuthenticate.getLogData();
                    exportStringFileName = "auth0d_ev2.html";
                    writeToUiToast("your authentication log file is ready for export");

                    //showDialog(MainActivity.this, desfireAuthenticate.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        authD1D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read&write access key = 01...
                clearOutputFields();
                String logString = "authenticate with DEFAULT DES key number 0x01 = read & write access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                //boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_DES_DEFAULT);
                boolean success = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_DES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticateLegacy.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData

                    // prepare data for export
                    exportString = desfireAuthenticate.getLogData();
                    exportStringFileName = "auth1d_ev2.html";
                    writeToUiToast("your authentication log file is ready for export");

                    //showDialog(MainActivity.this, desfireAuthenticateLegacy.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(output, desfireAuthenticateLegacy.getLogData());
                }
            }
        });

        // this method is using the Legacy/Proximity class
        authD2D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read&write access key = 01...
                clearOutputFields();
                String logString = "authenticate with DEFAULT DES key number 0x02 = change access rights key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                //boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_DES_DEFAULT);
                boolean success = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_DES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticateLegacy.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData

                    // prepare data for export
                    exportString = desfireAuthenticate.getLogData();
                    exportStringFileName = "auth2d_ev2.html";
                    writeToUiToast("your authentication log file is ready for export");

                    //showDialog(MainActivity.this, desfireAuthenticateLegacy.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(output, desfireAuthenticateLegacy.getLogData());
                }
            }
        });
/*
        authD2D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the CAR key = 02...
                clearOutputFields();
                String logString = "authenticate with DEFAULT DES key number 0x02 = change access rights key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
               // this is the authentication method from the NFCJLIB, working correctly
                boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_DES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticate.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData
                    showDialog(MainActivity.this, desfireAuthenticate.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });
*/
        authD3D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read access key = 03...
                clearOutputFields();
                String logString = "authenticate with DEFAULT DES key number 0x03 = read access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_R_NUMBER, APPLICATION_KEY_R_DES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticate.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData

                    // prepare data for export
                    exportString = desfireAuthenticate.getLogData();
                    exportStringFileName = "auth3d_ev2.html";
                    writeToUiToast("your authentication log file is ready for export");

                    //showDialog(MainActivity.this, desfireAuthenticate.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        authD4D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the 4write access key = 04...
                clearOutputFields();
                String logString = "authenticate with DEFAULT DES key number 0x04 = write access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_W_NUMBER, APPLICATION_KEY_W_DES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticate.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData

                    // prepare data for export
                    exportString = desfireAuthenticate.getLogData();
                    exportStringFileName = "auth4d_ev2.html";
                    writeToUiToast("your authentication log file is ready for export");

                    //showDialog(MainActivity.this, desfireAuthenticate.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        /**
         * section for authentication with CHANGED DES key
         */

        // todo CHANGE this is using AES auth
        authD0DC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the application master access key = 00...
                clearOutputFields();
                String logString = "authenticate with DEFAULT AES key number 0x02 = CAR key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                boolean success = desfireAuthenticate.authenticateWithNfcjlibAes(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_AES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_AES = desfireAuthenticate.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_AES));
                    vibrateShort();
                    // show logData

                    // prepare data for export
                    exportString = desfireAuthenticate.getLogData();
                    exportStringFileName = "auth2a_nfcJ.html";
                    writeToUiToast("your authentication log file is ready for export");

                    //showDialog(MainActivity.this, desfireAuthenticate.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        // todo CHANGE this is using AES auth
        authD1DC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read&write access key = 01...
                clearOutputFields();
                //String logString = "authenticate with CHANGED DES key number 0x01 = read & write access key";
                String logString = "authenticate with DEFAULT AES key number 0x01 = read & write access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];

                boolean success = desfireAuthenticateLegacy.authenticateAes(APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_AES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_AES = desfireAuthenticateLegacy.getSessionKey();
                    IV = new byte[16]; // after a successful authentication the  IV is resetted to 16 zero bytes
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_AES));
                    vibrateShort();
                    // show logData

                    // prepare data for export
                    exportString = desfireAuthenticateLegacy.getLogData();
                    exportStringFileName = "auth2d_leg.html";
                    writeToUiToast("your authentication log file is ready for export");

                    //showDialog(MainActivity.this, desfireAuthenticateLegacy.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        // todo CHANGE - this is using AES auth
        authD2DC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the car key = 02...
                clearOutputFields();
                String logString = "authenticate with DEFAULT AES key number 0x02 = change access rights key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                //boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_DES);

                boolean success = desfireAuthenticateLegacy.authenticateAes(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_AES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_AES = desfireAuthenticateLegacy.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_AES));
                    vibrateShort();
                    // show logData

                    // prepare data for export
                    exportString = desfireAuthenticateLegacy.getLogData();
                    exportStringFileName = "auth2a_leg.html";
                    writeToUiToast("your authentication log file is ready for export");

                    //showDialog(MainActivity.this, desfireAuthenticateLegacy.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        // todo CHANGE: this is using AES EV2 First Authentication
        authD3DC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read access key = 03...
                clearOutputFields();
                String logString = "authenticate with DEFAULT AES key number 0x02 = change access rights key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];

                boolean success = desfireAuthenticateEv2.authenticateAesEv2First(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_AES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_AES = desfireAuthenticateLegacy.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_AES));
                    vibrateShort();
                    // show logData

                    // prepare data for export
                    exportString = desfireAuthenticateLegacy.getLogData();
                    exportStringFileName = "auth2a_ev2.html";
                    writeToUiToast("your authentication log file is ready for export");

                    //showDialog(MainActivity.this, desfireAuthenticateProximity.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        // todo CHANGE: this is using AES EV2 Non First Authentication
        authD4DC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read access key = 03...
                clearOutputFields();
                String logString = "authenticate with DEFAULT AES key number 0x02 = change access rights key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                // check that a previous successfull authentication with EV2First was run
                boolean ev2FirstSuccess = desfireAuthenticateEv2.isAuthenticateEv2FirstSuccess();
                if (!ev2FirstSuccess) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to successfully run an 'authenticate EV2 First' before, aborted", COLOR_RED);
                    return;
                }

                byte[] responseData = new byte[2];

                boolean success = desfireAuthenticateEv2.authenticateAesEv2NonFirst(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_AES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    //SESSION_KEY_DES = desfireAuthenticateProximity.getSessionKey();
                    // todo work with SesAuthENCKey
                    //writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData

                    // prepare data for export
                    exportString = desfireAuthenticate.getLogData();
                    exportStringFileName = "auth2a_ev2.html";
                    writeToUiToast("your authentication log file is ready for export");

                    //showDialog(MainActivity.this, desfireAuthenticateProximity.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

/*
        authD0DC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the application master access key = 00...
                clearOutputFields();
                String logString = "authenticate with CHANGED DES key number 0x00 = application master access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_DES);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticate.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData
                    showDialog(MainActivity.this, desfireAuthenticate.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });
 */

/*
        authD2DC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the car key = 02...
                clearOutputFields();
                String logString = "authenticate with CHANGED DES key number 0x02 = change access rights key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_DES);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticate.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData
                    showDialog(MainActivity.this, desfireAuthenticate.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });
*/
        /*
        authD3DC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read access key = 03...
                clearOutputFields();
                String logString = "authenticate with CHANGED DES key number 0x03 = read access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_R_NUMBER, APPLICATION_KEY_R_DES);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticate.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData
                    showDialog(MainActivity.this, desfireAuthenticate.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

         */
/*
        authD4DC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the write access key = 04...
                clearOutputFields();
                String logString = "authenticate with CHANGED DES key number 0x04 = write access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_W_NUMBER, APPLICATION_KEY_W_DES);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticate.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData
                    showDialog(MainActivity.this, desfireAuthenticate.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

 */


        /**
         * section for general handling
         */

        getTagVersion.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // get the tag version data
                clearOutputFields();
                String logString = "getCardVersion";
                writeToUiAppend(output, logString);

                // this predefined in the header
                // GET_VERSION_COMMAND = (byte) 0x60;

                // manually building the command string
                byte[] command = new byte[5];
                command[0] = (byte) 0x90; // fixed as trailer for wrapped commands
                command[1] = GET_VERSION_COMMAND;
                command[2] = (byte) 0x00; // is 0x00
                command[3] = (byte) 0x00; // length of data, i 0 because we do not have any additional data to send
                command[4] = (byte) 0x00; // trailing '00'
                writeToUiAppend(output, "build the getVersion command manually");
                writeToUiAppend(output, printData("command", command));

                // we are sending this command to the PICC
                byte[] response = new byte[0];
                try {
                    response = isoDep.transceive(command);
                    writeToUiAppend(output, printData("response from PICC", response));
                } catch (NullPointerException e) {
                    Log.e(TAG, logString + " transceive failed, NullPointerException:\n" + e.getMessage());
                    writeToUiAppend(output, "transceive failed, did you forget to tap a tag first ? : " + e.getMessage());
                    return;
                } catch (IOException e) {
                    Log.e(TAG, logString + " transceive failed, IOException:\n" + e.getMessage());
                    writeToUiAppend(output, "transceive failed: " + e.getMessage());
                    return;
                }
                // example response: length: 9 data: 0401013300160591af

                writeToUiAppend(output, "we received two information's from PICC:");
                byte[] responseData1 = Arrays.copyOfRange(response, 0, response.length - 2);
                byte[] responseStatus1 = Arrays.copyOfRange(response, response.length - 2, response.length);
                writeToUiAppend(output, printData("responseData1", responseData1));
                writeToUiAppend(output, printData("responseStatus1", responseStatus1));

                // check for status == '0x90af
                final byte[] statusMoreData = new byte[]{(byte) 0x91, (byte) 0xAF};
                // check for status == '0x00
                final byte[] statusOk = new byte[]{(byte) 0x91, (byte) 0x00};

                boolean isResponseStatus1MoreData = Arrays.equals(responseStatus1, statusMoreData);
                writeToUiAppend(output, "checking that more data will follow from PICC: " + isResponseStatus1MoreData);
                if (!isResponseStatus1MoreData) {
                    writeToUiAppend(output, "no more data following, end requesting more data");
                    return;
                }

                // now we are asking to get more data from PICC

                // this predefined in the header
                // MORE_DATA_COMMAND = (byte) 0xAF;

                // manually building the command string
                command = new byte[5];
                command[0] = (byte) 0x90; // fixed as trailer for wrapped commands
                command[1] = MORE_DATA_COMMAND;
                command[2] = (byte) 0x00; // is 0x00
                command[3] = (byte) 0x00; // length of data, i 0 because we do not have any additional data to send
                command[4] = (byte) 0x00; // trailing '00'
                writeToUiAppend(output, "build the getMoreData command manually");
                writeToUiAppend(output, printData("command", command));

                // we are sending this command to the PICC
                response = new byte[0];
                try {
                    response = isoDep.transceive(command);
                    writeToUiAppend(output, printData("response from PICC", response));
                } catch (NullPointerException e) {
                    Log.e(TAG, logString + " transceive failed, NullPointerException:\n" + e.getMessage());
                    writeToUiAppend(output, "transceive failed, did you forget to tap a tag first ? : " + e.getMessage());
                    return;
                } catch (IOException e) {
                    Log.e(TAG, logString + " transceive failed, IOException:\n" + e.getMessage());
                    writeToUiAppend(output, "transceive failed: " + e.getMessage());
                    return;
                }
                // example response: length: 9 data: 0401010300160591af

                writeToUiAppend(output, "we received two information's from PICC:");
                byte[] responseData2 = Arrays.copyOfRange(response, 0, response.length - 2);
                byte[] responseStatus2 = Arrays.copyOfRange(response, response.length - 2, response.length);
                writeToUiAppend(output, printData("responseData2", responseData2));
                writeToUiAppend(output, printData("responseStatus2", responseStatus2));

                // check for status == '0x90af
                boolean isResponseStatus2MoreData = Arrays.equals(responseStatus2, statusMoreData);
                writeToUiAppend(output, "checking that more data will follow from PICC: " + isResponseStatus2MoreData);
                if (!isResponseStatus2MoreData) {
                    writeToUiAppend(output, "no more data following, end requesting more data");
                    return;
                }

                // now we are asking to get more data from PICC a second time

                // this predefined in the header
                // MORE_DATA_COMMAND = (byte) 0xAF;

                // manually building the command string
                command = new byte[5];
                command[0] = (byte) 0x90; // fixed as trailer for wrapped commands
                command[1] = MORE_DATA_COMMAND;
                command[2] = (byte) 0x00; // is 0x00
                command[3] = (byte) 0x00; // length of data, i 0 because we do not have any additional data to send
                command[4] = (byte) 0x00; // trailing '00'
                writeToUiAppend(output, "build the getMoreData command manually");
                writeToUiAppend(output, printData("command", command));

                // we are sending this command to the PICC
                response = new byte[0];
                try {
                    response = isoDep.transceive(command);
                    writeToUiAppend(output, printData("response from PICC", response));
                } catch (NullPointerException e) {
                    Log.e(TAG, logString + " transceive failed, NullPointerException:\n" + e.getMessage());
                    writeToUiAppend(output, "transceive failed, did you forget to tap a tag first ? : " + e.getMessage());
                    return;
                } catch (IOException e) {
                    Log.e(TAG, logString + " transceive failed, IOException:\n" + e.getMessage());
                    writeToUiAppend(output, "transceive failed: " + e.getMessage());
                    return;
                }
                // example response: length: 16 data: 04597a32501490204664303048229100

                writeToUiAppend(output, "we received two information's from PICC:");
                byte[] responseData3 = Arrays.copyOfRange(response, 0, response.length - 2);
                byte[] responseStatus3 = Arrays.copyOfRange(response, response.length - 2, response.length);
                writeToUiAppend(output, printData("responseData3", responseData3));
                writeToUiAppend(output, printData("responseStatus3", responseStatus3));

                // check for status == '0x90af
                boolean isResponseStatus3MoreData = Arrays.equals(responseStatus3, statusMoreData);
                writeToUiAppend(output, "checking that more data will follow from PICC: " + isResponseStatus3MoreData);
                if (isResponseStatus3MoreData) {
                    writeToUiAppend(output, "no more data following, end requesting more data");
                    return;
                }

                // check for status == '0x9000
                boolean isResponseStatus3Ok = Arrays.equals(responseStatus3, statusOk);
                writeToUiAppend(output, "checking that the status is OK" + isResponseStatus3Ok);
                if (!isResponseStatus3Ok) {
                    writeToUiAppend(output, "final status is not '0x9100', aborted");
                    return;
                }
                // now the status is OK and we can analyze the  data
                writeToUiAppend(output, "The final status is '0x9100' means SUCCESS");

                // concatenate the 3 parts
                writeToUiAppend(output, "concatenate the 3 response parts");
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write(responseData1, 0, responseData1.length);
                baos.write(responseData2, 0, responseData2.length);
                baos.write(responseData3, 0, responseData3.length);
                byte[] responseData = baos.toByteArray();
                writeToUiAppend(output, printData("complete responseData", responseData));
                // example length: 28 data: 040101330016050401010300160504597a3250149020466430304822

                // for analysis see the document MIFARE DESFire Light contactless application IC MF2DLHX0.pdf
                // on pages 67 - 69

                // to identify the hardware type see Mifare type identification procedure AN10833.pdf page 5

                // taking just some elements
                byte hardwareType = responseData[1];
                byte hardwareStorageSize = responseData[5];
                byte weekProduction = responseData[26];
                byte yearProduction = responseData[27];

                String hardwareTypeName = " is not a Mifare DESFire tag";
                if (hardwareType == (byte) 0x01) hardwareTypeName = " is a Mifare DESFire tag";
                int hardwareStorageSizeInt = (int) Math.pow(2, hardwareStorageSize >> 1); // get the storage size in bytes

                writeToUiAppend(output, "hardwareType: " + Utils.byteToHex(hardwareType) + hardwareTypeName);
                writeToUiAppend(output, "hardwareStorageSize (byte): " + Utils.byteToHex(hardwareStorageSize));
                writeToUiAppend(output, "hardwareStorageSize (int): " + hardwareStorageSizeInt);
                writeToUiAppend(output, "weekProduction: " + Utils.byteToHex(weekProduction));
                writeToUiAppend(output, "yearProduction: " + Utils.byteToHex(yearProduction));

                vibrateShort();

                /*
                VersionInfo versionInfo = null;
                try {
                    versionInfo = getVersionInfo(output);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "success in getting tagVersion", COLOR_GREEN);
                } catch (Exception e) {
                    //throw new RuntimeException(e);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "getTagVersion Exception: " + e.getMessage(), COLOR_RED);
                    e.printStackTrace();
                }
                if (versionInfo != null) {
                    writeToUiAppend(output, versionInfo.dump());
                }

                 */
            }
        });


        getCardUidDes.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                // status: WORKING

                clearOutputFields();
                String logString = "get card UID (DES encrypted)";
                writeToUiAppend(output, logString);
                // check that an authentication was done before ?

                byte[] responseData = new byte[2];
                byte[] result = getCardUid(output, responseData);
                if (result == null) {
                    // something gone wrong
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkResponseMoreData(responseData)) {
                        writeToUiAppend(output, "the data I'm receiving is too long to read, sorry");
                    }
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with any key ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                } else {
                    writeToUiAppend(output, logString + printData(" UID", result));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);

                    // correct result is 04597a32501490 (7 bytes)
                    // encrypt result is length: 16 data: f3cea1277fde140b04513f15412904e9
                    // decrypt result is length: 16 data: 04597a32501490074400000000000000
                    // correct result is                  04597a32501490 (7 bytes)
                    byte[] encryptionKeyDes = SESSION_KEY_DES;
                    byte[] encryptionKeyTDes = desfireAuthenticateLegacy.getTDesKeyFromDesKey(encryptionKeyDes);

                    writeToUiAppend(output, printData("encryptionKey DES", encryptionKeyDes));
                    writeToUiAppend(output, printData("encryptionKey TDES", encryptionKeyTDes));
                    writeToUiAppend(output, printData("encrypted UID", result));
                    byte[] iv = new byte[8]; // a DES IV is 8 bytes long
                    writeToUiAppend(output, printData("IV", iv));
                    byte[] decryptedData = TripleDES.decrypt(iv, encryptionKeyTDes, result);
                    writeToUiAppend(output, printData("decryptedData", decryptedData));
                    // decryptedData is 7 bytes UID || 2 bytes CRC16 || 7 bytes RFU = 00's
                    byte[] cardUid = Arrays.copyOfRange(decryptedData, 0, 7);
                    byte[] crc16Received = Arrays.copyOfRange(decryptedData, 7, 9);
                    writeToUiAppend(output, printData("cardUid", cardUid));
                    writeToUiAppend(output, printData("crc16 received", crc16Received));

                    // check crc16 over received DATA (only)
                    int cardUidLength = 7;
                    byte[] crc16Data = new byte[cardUidLength];
                    System.arraycopy(decryptedData, 0, crc16Data, 0, cardUidLength);
                    byte[] crc16Calculated = CRC16.get(crc16Data);
                    writeToUiAppend(output, printData("crc16 calcultd", crc16Calculated));
                    if (Arrays.equals(crc16Received, crc16Calculated)) {
                        writeToUiAppend(output, "CRC16 matches calculated CRC16");
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " CRC16 DOES match calculated CRC16", COLOR_GREEN);
                    } else {
                        writeToUiAppend(output, "CRC16 DOES NOT matches calculated CRC16");
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " CRC16 DOES NOT matches calculated CRC16", COLOR_RED);
                        return;
                    }
                    vibrateShort();
                }
            }
        });

        getCardUidAes.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                // status: NOT working, wrong cardUID
                // for CMAC see https://stackoverflow.com/questions/20503060/how-to-decrypt-the-first-message-sent-from-mifare-desfire-ev1

                clearOutputFields();
                String logString = "get card UID (AES encrypted)";
                writeToUiAppend(output, logString);
                // check that an authentication was done before ?

                byte[] responseData = new byte[2];

                // no parameter
                byte[] response = new byte[0];
                byte[] apdu = new byte[0];
                byte[] encryptedData;
                try {
                    apdu = wrapMessage(GET_CARD_UID_COMMAND, null);
                    Log.d(TAG, logString + printData(" apdu", apdu));
                    response = isoDep.transceive(apdu);
                    Log.d(TAG, logString + printData(" response", response));
                } catch (IOException e) {
                    Log.e(TAG, logString + " transceive failed, IOException:\n" + e.getMessage());
                    writeToUiAppend(output, "transceive failed: " + e.getMessage());
                    System.arraycopy(RESPONSE_FAILURE, 0, responseData, 0, 2);
                    return;
                }
                byte[] responseBytes = returnStatusBytes(response);
                System.arraycopy(responseBytes, 0, responseData, 0, 2);
                if (checkResponse(response)) {
                    Log.d(TAG, logString + " SUCCESS");
                    encryptedData = Arrays.copyOf(response, response.length - 2);
                } else {
                    Log.d(TAG, logString + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
                    Log.d(TAG, logString + " error code: " + EV3.getErrorCode(responseBytes));
                    return;
                }
                /*
                byte[] result = getCardUid(output, responseData);
                if (result == null) {
                    // something gone wrong
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkResponseMoreData(responseData)) {
                        writeToUiAppend(output, "the data I'm receiving is too long to read, sorry");
                    }
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with any key ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                } else {
                    writeToUiAppend(output, logString + printData(" UID", result));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                }
                */
                // correct result is 045e0832501490 (7 bytes)
                // encrypt result is length: 16 data: 359734583048c7ea0e6352f0478c6068
                // decrypt result is length: 16 data: 7a4f24afd255ab778cbc1b9fae1c6cad
                // correct result is                  045e0832501490 (7 bytes)
                byte[] encryptionKeyAes = SESSION_KEY_AES;
                writeToUiAppend(output, printData("encryptionKey AES", encryptionKeyAes));

                byte[] iv = IV.clone(); // an AES IV is 16 bytes long
                writeToUiAppend(output, printData("IV", iv));
                writeToUiAppend(output, printData("apdu", apdu));
                byte[] cmacIv = calculateApduCMAC(apdu, encryptionKeyAes, iv);
                writeToUiAppend(output, printData("cmacIv", cmacIv));
                writeToUiAppend(output, printData("encrypted data", encryptedData));

                byte[] decryptedData = AES.decrypt(cmacIv, encryptionKeyAes, encryptedData);
                writeToUiAppend(output, printData("decryptedData", decryptedData));
                // decryptedData is 7 bytes UID || 4 bytes CRC32 || 5 bytes RFU = 00's
                byte[] cardUid = Arrays.copyOfRange(decryptedData, 0, 7);
                byte[] crc32Received = Arrays.copyOfRange(decryptedData, 7, 11);
                writeToUiAppend(output, printData("cardUid", cardUid));
                writeToUiAppend(output, printData("crc32 received", crc32Received));

                // check crc32 over received DATA (only)
                int cardUidLength = 7;
                byte[] crc32Calculated = calculateApduCRC32R(decryptedData, cardUidLength);
                writeToUiAppend(output, printData("crc32 calcultd", crc32Calculated));
                if (Arrays.equals(crc32Received, crc32Calculated)) {
                    writeToUiAppend(output, "CRC32 matches calculated CRC32");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " CRC32 DOES match calculated CRC32", COLOR_GREEN);
                } else {
                    writeToUiAppend(output, "CRC32 DOES NOT matches calculated CRC32");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " CRC16 DOES NOT matches calculated CRC16", COLOR_RED);
                    return;
                }
                // set the new global IV
                IV = encryptedData.clone();
                writeToUiAppend(output, "new global IV is" + printData("", IV));
                vibrateShort();

                // original AES card: 045e0832501490
                // decr               046feadd1b0e57
            }
        });

        formatPicc.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // get the free memory on the tag
                clearOutputFields();
                String logString = "format the PICC";
                writeToUiAppend(output, logString);

                // open a confirmation dialog
                DialogInterface.OnClickListener dialogClickListener = new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        switch (which) {
                            case DialogInterface.BUTTON_POSITIVE:
                                //Yes button clicked

                                boolean success = desfireAuthenticateLegacy.formatPicc();
                                byte[] responseData = desfireAuthenticateLegacy.getErrorCode();
                                if (success) {
                                    writeToUiAppend(output, logString + " SUCCESS");
                                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                                    vibrateShort();
                                } else {
                                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                                }
                                break;
                            case DialogInterface.BUTTON_NEGATIVE:
                                //No button clicked
                                // nothing to do
                                writeToUiAppend(output, "format of the PICC aborted");
                                break;
                        }
                    }
                };
                final String selectedFolderString = "You are going to format the PICC " + "\n\n" +
                        "Do you want to proceed ?";
                AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);

                builder.setMessage(selectedFolderString).setPositiveButton(android.R.string.yes, dialogClickListener)
                        .setNegativeButton(android.R.string.no, dialogClickListener)
                        .setTitle("FORMAT the PICC")
                        .show();
        /*
        If you want to use the "yes" "no" literals of the user's language you can use this
        .setPositiveButton(android.R.string.yes, dialogClickListener)
        .setNegativeButton(android.R.string.no, dialogClickListener)
         */
            }
        });


        /**
         * section for DES visualizing
         */

        selectApplicationDesVisualizing.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "DES visualizing select an application";
                writeToUiAppend(output, logString);
                //byte[] applicationIdentifier = hexStringToByteArray("0100D0"); // lsb
                byte[] applicationIdentifier = hexStringToByteArray("D00001");
                applicationId.setText("D00001");
                if (applicationIdentifier == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you entered a wrong application ID", COLOR_RED);
                    return;
                }
                //Utils.reverseByteArrayInPlace(applicationIdentifier); // change to LSB = change the order
                if (applicationIdentifier.length != 3) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you did not enter a 6 hex string application ID", COLOR_RED);
                    return;
                }
                writeToUiAppend(output, logString + " with id: " + applicationId.getText().toString());
                byte[] responseData = new byte[2];
                boolean success = desfireAuthenticateLegacy.selectApplication(applicationIdentifier);
                responseData = desfireAuthenticateLegacy.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    selectedApplicationId = applicationIdentifier.clone();
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        authDesVisualizing.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read&write access key = 01...
                clearOutputFields();
                String logString = "DES visualizing authenticate with DEFAULT DES key number 0x01 = read & write access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                //boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_DES_DEFAULT);
                boolean success = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_DES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticateLegacy.getSessionKey();
                    writeToUiAppend(output, printData("the DES session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData

                    // prepare data for export
                    exportString = desfireAuthenticateLegacy.getLogData();
                    exportStringFileName = "auth1d_ev2.html";
                    writeToUiToast("your authentication log file is ready for export");

                    //showDialog(MainActivity.this, desfireAuthenticateLegacy.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(output, desfireAuthenticateLegacy.getLogData());
                }
            }
        });

        authDesVisualizingC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read&write access key = 01...
                clearOutputFields();
                String logString = "DES visualizing authenticate with CHANGED DES key number 0x01 = read & write access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                //boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_DES_DEFAULT);
                boolean success = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_DES);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticateLegacy.getSessionKey();
                    writeToUiAppend(output, printData("the DES session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData

                    // prepare data for export
                    exportString = desfireAuthenticateLegacy.getLogData();
                    Log.d(TAG, "exportString: " + exportString);
                    exportStringFileName = "auth1d_ev2.html";
                    writeToUiToast("your authentication log file is ready for export");

                    //showDialog(MainActivity.this, desfireAuthenticateLegacy.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(output, desfireAuthenticateLegacy.getLogData());
                }
            }
        });

        authDesVisualizingC2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read&write access key = 01...
                clearOutputFields();
                String logString = "DES visualizing authenticate with CHANGED 2 DES key number 0x01 = read & write access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                //boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_DES_DEFAULT);
                boolean success = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_DES_2);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticateLegacy.getSessionKey();
                    writeToUiAppend(output, printData("the DES session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData

                    // prepare data for export
                    exportString = desfireAuthenticateLegacy.getLogData();
                    exportStringFileName = "auth1d_ev2.html";
                    writeToUiToast("your authentication log file is ready for export");

                    //showDialog(MainActivity.this, desfireAuthenticateLegacy.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(output, desfireAuthenticateLegacy.getLogData());
                }
            }
        });

        readDesVisualizing.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "DES visualizing read from an encrypted standard file";
                writeToUiAppend(output, logString);
                // check that a file was selected before
                selectedFileId = "1";
                fileSelected.setText("1");

                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte fileIdByte = Byte.parseByte(selectedFileId);
                byte[] responseData = new byte[2];
                byte[] result = desfireAuthenticateLegacy.readFromAStandardFileEncipheredCommunicationDes(fileIdByte, selectedFileSize);
                responseData = desfireAuthenticateLegacy.getErrorCode();
                Log.d(TAG, desfireAuthenticateLegacy.getLogData());
                if (result == null) {
                    // something gone wrong
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkResponseMoreData(responseData)) {
                        writeToUiAppend(output, "the file is too long to read, sorry");
                    }
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a READ ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                } else {
                    writeToUiAppend(output, logString + " ID: " + fileIdByte + printData(" data", result));
                    writeToUiAppend(output, logString + " ID: " + fileIdByte + " data: " + new String(result, StandardCharsets.UTF_8));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                }
            }
        });

        writeDesVisualizing.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "DES visualizing write to an encrypted standard file";
                writeToUiAppend(output, logString);
                // check that a file was selected before

                selectedFileId = "1";
                fileSelected.setText("1");
                selectedFileSize = 32;

                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }

                // we are writing an timestamp to the standard file
                String dataToWrite = Utils.getTimestamp();
                /*
                String dataToWrite = fileStandardData.getText().toString();
                if (TextUtils.isEmpty(dataToWrite)) {
                    //writeToUiAppend(errorCode, "please enter some data to write");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "please enter some data to write", COLOR_RED);
                    return;
                }

                 */
                byte[] dataToWriteBytes = dataToWrite.getBytes(StandardCharsets.UTF_8);

                // create an empty array and copy the dataToWrite to clear the complete standard file
                byte[] fullDataToWrite = new byte[selectedFileSize];
                System.arraycopy(dataToWriteBytes, 0, fullDataToWrite, 0, dataToWriteBytes.length);

                byte fileIdByte = Byte.parseByte(selectedFileId);
                byte[] responseData = new byte[2];
                boolean success = desfireAuthenticateLegacy.writeToAStandardFileEncipheredCommunicationDes(fileIdByte, fullDataToWrite);
                responseData = desfireAuthenticateLegacy.getErrorCode();
                Log.d(TAG, desfireAuthenticateLegacy.getLogData());
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a WRITE ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        changeKeyDes01ToChangedDesVisualizing.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this method will change the key number 1 (read&write access) from default to D100...
                clearOutputFields();
                String logString = "DES visualizing change key 1 read&write access to CHANGED";
                writeToUiAppend(output, logString);

                byte[] responseData = new byte[2];
                writeToUiAppend(output, "changeKeyDes: "
                        + Utils.byteToHex(APPLICATION_KEY_RW_NUMBER)
                        + " from " + printData("oldValue", APPLICATION_KEY_RW_DES_DEFAULT)
                        + " to " + printData("newValue", APPLICATION_KEY_RW_DES));

                // select the application
                writeToUiAppend(output, "step 1: select the application");
                byte[] applicationIdentifier = hexStringToByteArray("0100D0"); // lsb
                applicationId.setText("D00001");
                writeToUiAppend(output, "select the application with id: " + applicationId.getText().toString());
                boolean success = desfireAuthenticateLegacy.selectApplication(applicationIdentifier);
                responseData = desfireAuthenticateLegacy.getErrorCode();
                if (success) {
                    writeToUiAppend(output, "select the application SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "select the application SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "select the application FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                }

                // before we are running an auth with key 0 (application master key)
                writeToUiAppend(output, "step 2: authenticate with the app MASTER key");
                success = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_DES_DEFAULT);
                //boolean success = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_DES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, "auth with app MASTER key SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "auth with app MASTER key SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticateLegacy.getSessionKey();
                    KEY_NUMBER_USED_FOR_AUTHENTICATION = APPLICATION_KEY_MASTER_NUMBER;
                    writeToUiAppend(output, printData("the DES session key is", SESSION_KEY_DES));
                    vibrateShort();
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "auth with app MASTER key FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(output, desfireAuthenticateLegacy.getLogData());
                    return;
                }

                // now change the key
                writeToUiAppend(output, "step 3: change key 1 to CHANGED");
                success = desfireAuthenticateLegacy.changeDesKey(KEY_NUMBER_USED_FOR_AUTHENTICATION, APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_DES, APPLICATION_KEY_RW_DES_DEFAULT, "read&write access");
                responseData = desfireAuthenticateLegacy.getErrorCode();
                Log.d(TAG, desfireAuthenticateLegacy.getLogData());

                if (success) {
                    writeToUiAppend(output, "change key 1 to CHANGED SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "change key 1 to CHANGED SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "change key 1 to CHANGED FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                }
            }
        });

        changeKeyDes01ToDefaultDesVisualizing.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this method will change the key number 1 (read&write access) from changed to DEFAULT
                clearOutputFields();
                String logString = "DES visualizing change key 1 read&write access to DEFAULT";
                writeToUiAppend(output, logString);

                byte[] responseData = new byte[2];
                writeToUiAppend(output, "changeKeyDes: "
                        + Utils.byteToHex(APPLICATION_KEY_RW_NUMBER)
                        + " from " + printData("oldValue", APPLICATION_KEY_RW_DES)
                        + " to " + printData("newValue", APPLICATION_KEY_RW_DES_DEFAULT));

                // select the application
                writeToUiAppend(output, "step 1: select the application");
                byte[] applicationIdentifier = hexStringToByteArray("0100D0"); // lsb
                applicationId.setText("D00001");
                writeToUiAppend(output, "select the application with id: " + applicationId.getText().toString());
                boolean success = desfireAuthenticateLegacy.selectApplication(applicationIdentifier);
                responseData = desfireAuthenticateLegacy.getErrorCode();
                if (success) {
                    writeToUiAppend(output, "select the application SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "select the application SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "select the application FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                }

                // before we are running an auth with key 0 (application master key)
                writeToUiAppend(output, "step 2: authenticate with the app MASTER key");
                success = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_DES_DEFAULT);
                //boolean success = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_DES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, "auth with app MASTER key SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "auth with app MASTER key SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticateLegacy.getSessionKey();
                    KEY_NUMBER_USED_FOR_AUTHENTICATION = APPLICATION_KEY_MASTER_NUMBER;
                    writeToUiAppend(output, printData("the DES session key is", SESSION_KEY_DES));
                    vibrateShort();
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "auth with app MASTER key FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(output, desfireAuthenticateLegacy.getLogData());
                    return;
                }

                // now change the key
                writeToUiAppend(output, "step 3: change key 1 to DEFAULT");
                success = desfireAuthenticateLegacy.changeDesKey(KEY_NUMBER_USED_FOR_AUTHENTICATION, APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_DES_DEFAULT, APPLICATION_KEY_RW_DES, "read&write access");
                responseData = desfireAuthenticateLegacy.getErrorCode();
                Log.d(TAG, desfireAuthenticateLegacy.getLogData());
                if (success) {
                    writeToUiAppend(output, "change key 1 to DEFAULT SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "change key 1 to DEFAULT SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "change key 1 to DEFAULT FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                }
            }
        });

        changeKeyDes01ToChanged2DesVisualizing.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this method will change the key number 1 (read&write access) from default to D100...
                clearOutputFields();
                String logString = "DES visualizing change key 1 read&write access from CHANGED to CHANGED 2";
                writeToUiAppend(output, logString);

                byte[] responseData = new byte[2];
                writeToUiAppend(output, "changeKeyDes: "
                        + Utils.byteToHex(APPLICATION_KEY_RW_NUMBER)
                        + " from " + printData("oldValue", APPLICATION_KEY_RW_DES)
                        + " to " + printData("newValue", APPLICATION_KEY_RW_DES_2));

                // select the application
                writeToUiAppend(output, "step 1: select the application");
                byte[] applicationIdentifier = hexStringToByteArray("0100D0"); // lsb
                applicationId.setText("D00001");
                writeToUiAppend(output, "select the application with id: " + applicationId.getText().toString());
                boolean success = desfireAuthenticateLegacy.selectApplication(applicationIdentifier);
                responseData = desfireAuthenticateLegacy.getErrorCode();
                if (success) {
                    writeToUiAppend(output, "select the application SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "select the application SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "select the application FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                }

                // before we are running an auth with key 0 (application master key)
                writeToUiAppend(output, "step 2: authenticate with the app MASTER key");
                success = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_DES_DEFAULT);
                //boolean success = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_DES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, "auth with app MASTER key SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "auth with app MASTER key SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticateLegacy.getSessionKey();
                    KEY_NUMBER_USED_FOR_AUTHENTICATION = APPLICATION_KEY_MASTER_NUMBER;
                    writeToUiAppend(output, printData("the DES session key is", SESSION_KEY_DES));
                    vibrateShort();
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "auth with app MASTER key FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(output, desfireAuthenticateLegacy.getLogData());
                    return;
                }

                // now change the key
                writeToUiAppend(output, "step 3: change key 1 to CHANGED 2");
                success = desfireAuthenticateLegacy.changeDesKey(KEY_NUMBER_USED_FOR_AUTHENTICATION, APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_DES_2, APPLICATION_KEY_RW_DES, "read&write access");
                responseData = desfireAuthenticateLegacy.getErrorCode();
                Log.d(TAG, desfireAuthenticateLegacy.getLogData());

                if (success) {
                    writeToUiAppend(output, "change key 1 to CHANGED 2 SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "change key 1 to CHANGED SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "change key 1 to CHANGED 2 FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                }
            }
        });

        changeKeyDes01ToDefault2DesVisualizing.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this method will change the key number 1 (read&write access) from changed to DEFAULT
                clearOutputFields();
                String logString = "DES visualizing change key 1 read&write access from CHANGED 2 to DEFAULT";
                writeToUiAppend(output, logString);

                byte[] responseData = new byte[2];
                writeToUiAppend(output, "changeKeyDes: "
                        + Utils.byteToHex(APPLICATION_KEY_RW_NUMBER)
                        + " from " + printData("oldValue", APPLICATION_KEY_RW_DES_2)
                        + " to " + printData("newValue", APPLICATION_KEY_RW_DES_DEFAULT));

                // select the application
                writeToUiAppend(output, "step 1: select the application");
                byte[] applicationIdentifier = hexStringToByteArray("0100D0"); // lsb
                applicationId.setText("D00001");
                writeToUiAppend(output, "select the application with id: " + applicationId.getText().toString());
                boolean success = desfireAuthenticateLegacy.selectApplication(applicationIdentifier);
                responseData = desfireAuthenticateLegacy.getErrorCode();
                if (success) {
                    writeToUiAppend(output, "select the application SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "select the application SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "select the application FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                }

                // before we are running an auth with key 0 (application master key)
                writeToUiAppend(output, "step 2: authenticate with the app MASTER key");
                success = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_DES_DEFAULT);
                //boolean success = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_DES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, "auth with app MASTER key SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "auth with app MASTER key SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticateLegacy.getSessionKey();
                    KEY_NUMBER_USED_FOR_AUTHENTICATION = APPLICATION_KEY_MASTER_NUMBER;
                    writeToUiAppend(output, printData("the DES session key is", SESSION_KEY_DES));
                    vibrateShort();
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "auth with app MASTER key FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(output, desfireAuthenticateLegacy.getLogData());
                    return;
                }

                // now change the key
                writeToUiAppend(output, "step 3: change key 1 to DEFAULT");
                success = desfireAuthenticateLegacy.changeDesKey(KEY_NUMBER_USED_FOR_AUTHENTICATION, APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_DES_DEFAULT, APPLICATION_KEY_RW_DES_2, "read&write access");
                responseData = desfireAuthenticateLegacy.getErrorCode();
                Log.d(TAG, desfireAuthenticateLegacy.getLogData());
                if (success) {
                    writeToUiAppend(output, "change key 1 to DEFAULT SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "change key 1 to DEFAULT SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "change key 1 to DEFAULT FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                }
            }
        });

        changeKeyDes00ToChangedDesVisualizing.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this method will change the key number 0 (master) from default to D100...
                clearOutputFields();
                String logString = "DES visualizing change key 0 app Master to CHANGED";
                writeToUiAppend(output, logString);

                byte[] responseData = new byte[2];
                writeToUiAppend(output, "changeKeyDes: "
                        + Utils.byteToHex(APPLICATION_KEY_MASTER_NUMBER)
                        + " from " + printData("oldValue", APPLICATION_KEY_MASTER_DES_DEFAULT)
                        + " to " + printData("newValue", APPLICATION_KEY_MASTER_DES));

                // select the application
                writeToUiAppend(output, "step 1: select the application");
                byte[] applicationIdentifier = hexStringToByteArray("0100D0"); // lsb
                applicationId.setText("D00001");
                writeToUiAppend(output, "select the application with id: " + applicationId.getText().toString());
                boolean success = desfireAuthenticateLegacy.selectApplication(applicationIdentifier);
                responseData = desfireAuthenticateLegacy.getErrorCode();
                if (success) {
                    writeToUiAppend(output, "select the application SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "select the application SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "select the application FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                }

                // before we are running an auth with key 0 (application master key)
                writeToUiAppend(output, "step 2: authenticate with the app MASTER key");
                success = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_DES_DEFAULT);
                //boolean success = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_DES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, "auth with app MASTER key SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "auth with app MASTER key SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticateLegacy.getSessionKey();
                    KEY_NUMBER_USED_FOR_AUTHENTICATION = APPLICATION_KEY_MASTER_NUMBER;
                    writeToUiAppend(output, printData("the DES session key is", SESSION_KEY_DES));
                    vibrateShort();
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "auth with app MASTER key FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(output, desfireAuthenticateLegacy.getLogData());
                    return;
                }

                // now change the key
                writeToUiAppend(output, "step 3: change key 0 to CHANGED");
                success = desfireAuthenticateLegacy.changeDesKey(KEY_NUMBER_USED_FOR_AUTHENTICATION, APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_DES, APPLICATION_KEY_MASTER_DES_DEFAULT, "app master");
                responseData = desfireAuthenticateLegacy.getErrorCode();
                Log.d(TAG, desfireAuthenticateLegacy.getLogData());
                if (success) {
                    writeToUiAppend(output, "change key 0 to CHANGED SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "change key 0 to CHANGED SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "change key 0 to CHANGED FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                }
            }
        });

        changeKeyDes00ToDefaultDesVisualizing.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // this method will change the key number 0 (application master) from changed to DEFAULT
                clearOutputFields();
                String logString = "DES visualizing change key 0 application master to DEFAULT";
                writeToUiAppend(output, logString);

                byte[] responseData = new byte[2];
                writeToUiAppend(output, "changeKeyDes: "
                        + Utils.byteToHex(APPLICATION_KEY_MASTER_NUMBER)
                        + " from " + printData("oldValue", APPLICATION_KEY_MASTER_DES)
                        + " to " + printData("newValue", APPLICATION_KEY_MASTER_DES_DEFAULT));

                // select the application
                writeToUiAppend(output, "step 1: select the application");
                byte[] applicationIdentifier = hexStringToByteArray("0100D0"); // lsb
                applicationId.setText("D00001");
                writeToUiAppend(output, "select the application with id: " + applicationId.getText().toString());
                boolean success = desfireAuthenticateLegacy.selectApplication(applicationIdentifier);
                responseData = desfireAuthenticateLegacy.getErrorCode();
                if (success) {
                    writeToUiAppend(output, "select the application SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "select the application SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "select the application FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                }

                // before we are running an auth with key 0 (application master key)
                writeToUiAppend(output, "step 2: authenticate with the CHANGED app MASTER key");
                success = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_DES);
                //boolean success = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_DES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, "auth with app MASTER key SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "auth with app MASTER key SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticateLegacy.getSessionKey();
                    KEY_NUMBER_USED_FOR_AUTHENTICATION = APPLICATION_KEY_MASTER_NUMBER;
                    writeToUiAppend(output, printData("the DES session key is", SESSION_KEY_DES));
                    vibrateShort();
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "auth with app MASTER key FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(output, desfireAuthenticateLegacy.getLogData());
                    return;
                }

                // now change the key
                writeToUiAppend(output, "step 3: change key 0 to DEFAULT");
                success = desfireAuthenticateLegacy.changeDesKey(KEY_NUMBER_USED_FOR_AUTHENTICATION, APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_DES_DEFAULT, APPLICATION_KEY_MASTER_DES, "app master");
                responseData = desfireAuthenticateLegacy.getErrorCode();
                Log.d(TAG, desfireAuthenticateLegacy.getLogData());
                if (success) {
                    writeToUiAppend(output, "change key 0 to DEFAULT SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "change key 0 to DEFAULT SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "change key 0 to DEFAULT FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                }
            }
        });

        getKeyVersion.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "getKeyVersion";
                writeToUiAppend(output, logString);

                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }

                byte[] responseData = new byte[2];
                List<Byte> result = ntag424DnaMethods.getAllKeyVersions();
                if (result.isEmpty()) {
                    writeToUiAppend(output, logString + " FAILURE");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                } else {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    for (int i = 0; i < result.size(); i++) {
                        writeToUiAppend(output, "keyNumber " + i + " keyVersion: " + result.get(i).toString());
                    }
                    vibrateShort();
                }
            }
        });

        /**
         * section for sdm handling
         */

        createNdefFile256Ev2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "SDM createNdefFile256";
                writeToUiAppend(output, logString);

                // this is running the complete workflow to setup an NDEF application
                // we do need an empty tag so best option is to format the tag before

                // select the master file application
                writeToUiAppend(output, "");
                writeToUiAppend(output, "1. MIFARE DESFire SelectApplication with AID equal to 000000h (PICC level)");
                boolean success = desfireAuthenticateEv2.selectApplicationByAidEv2(new byte[3]);
                if (!success) {
                    writeToUiAppend(output, "Error during SelectApplication with AID equal to 000000h (PICC level), aborted");
                    return;
                }

                byte[] AID_NDEF = Utils.hexStringToByteArray("010000"); // the AID is 00 00 01 but data is in low endian
                byte[] ISO_APPLICATION_ID = Utils.hexStringToByteArray("10E1"); // the AID is E110 but written in low endian
                byte APPLICATION_KEY_SETTINGS = (byte) 0x0F;
                byte numberOfKeys = (byte) 0x21; // number of keys: 1, TDES keys
                //byte COMMUNICATION_SETTINGS = (byte) 0x0f;
                byte FILE_ID_01 = (byte) 0x01;
                byte[] ISO_FILE_ID_01 = Utils.hexStringToByteArray("03E1"); // the file ID is E103 but written as low endian
                int FILE_01_SIZE = 15;

                byte FILE_ID_02 = (byte) 0x02;
                byte[] ISO_FILE_ID_02 = Utils.hexStringToByteArray("04E1");// the file ID is E104 but written as low endian
                int FILE_02_SIZE = 256; // NDEF FileSize equal to 000100h (256 Bytes)
                byte[] ISO_DF = Utils.hexStringToByteArray("D2760000850101"); // this is the AID for NDEF

                writeToUiAppend(output, "");
                writeToUiAppend(output, "2. MIFARE DESFire CreateApplication using the default AID 000001h");
                //success = desfireAuthenticateEv2.createNdefApplicationIsoDes(output);
                success = desfireAuthenticateEv2.createNdefApplicationIsoAes(output);
                if (!success) {
                    writeToUiAppend(output, "Error during CreateApplication using the default AID 000001h, aborted");
                    return;
                }

                writeToUiAppend(output, "");
                writeToUiAppend(output, "3. MIFARE DESFire SelectApplication (Select previously created application)");
                success = desfireAuthenticateEv2.selectNdefApplicationIso(output);
                if (!success) {
                    writeToUiAppend(output, "Error during SelectApplication using the default AID 000001h, aborted");
                    return;
                }

                // step 04 create the NDEF container = standard file
                writeToUiAppend(output, "");
                writeToUiAppend(output, "4. MIFARE DESFire NDEF Container CreateStdDataFile with FileNo equal to 01h");
                success = desfireAuthenticateEv2.createNdefContainerFileIso(output);
                if (!success) {
                    writeToUiAppend(output, "Error during NDEF Container CreateStdDataFile with FileNo equal to 01, aborted");
                    return;
                }

                // step 05 write to standard file
                writeToUiAppend(output, "");
                writeToUiAppend(output, "5. MIFARE DESFire WriteData to write the content of the CC File with CCLEN equal to 000Fh");
                success = desfireAuthenticateEv2.writeToNdefContainerFileIso(output);
                if (!success) {
                    writeToUiAppend(output, "Error during NDEF WriteData to write the content of the CC File with CCLEN equal to 000Fh, aborted");
                    return;
                }

                // step 06 create a standard file
                writeToUiAppend(output, "");
                writeToUiAppend(output, "6. MIFARE DESFire NDEF File2 CreateStdDataFile with FileNo equal to 02h SDM");
                //success = desfireAuthenticateEv2.createNdefFile2Iso(output); // this is the regular NDEF file 02 without SDM feature
                success = desfireAuthenticateEv2.createNdefFile2IsoSdm(output); // not working !
                if (!success) {
                    writeToUiAppend(output, "Error during NDEF File2 CreateStdDataFile with FileNo equal to 02, aborted");
                    return;
                }

                // step 07 write to standard file
                writeToUiAppend(output, "");
                writeToUiAppend(output, "7. MIFARE DESFire NDEF File2 WriteStdDataFile with FileNo equal to 02h");
                success = desfireAuthenticateEv2.writeToNdefFile2Iso(output);
                if (!success) {
                    writeToUiAppend(output, "Error during NDEF File2 CreateStdDataFile with FileNo equal to 02, aborted");
                    return;
                }
                writeToUiAppend(output, logString + " SUCCESS");
                vibrateShort();
                return;
            }
        });

        sdmChangeFileSettingsEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "SDM changeFileSettings";
                writeToUiAppend(output, logString);

                byte[] ndefApplication = hexStringToByteArray("010000"); // the AID is 00 00 01 but data is in low endian
                byte ndefFileId = (byte) 0x02;
                writeToUiAppend(output, "fileNumber (fixed): " + ndefFileId + printData(" ndefApplication", ndefApplication));

                byte[] responseData = new byte[2];
                writeToUiAppend(output, logString + " step 1: select ndef application");
                // select the application
                //boolean success = desfireAuthenticateLegacy.selectApplication(ndefApplication);
                //responseData = desfireAuthenticateLegacy.getErrorCode();
                //boolean success = desfireAuthenticateEv2.selectApplicationByAidEv2(ndefApplication);
                boolean success = desfireAuthenticateEv2.selectApplicationByDfNameIso(DesfireAuthenticateEv2.NDEF_APPLICATION_DF_NAME);

                responseData = desfireAuthenticateEv2.getErrorCode();
                if (success) {
                    writeToUiAppend(output, "select the application SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "select the application SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "select the application FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                }

                // don't forget to run an auth to get a SessionKey
                String logString2 = "step 2: EV2 First authenticate with DEFAULT AES key number 0x00 = application master key";
                writeToUiAppend(output, logString2);

                exportString = "";
                exportStringFileName = "auth.html";

                success = desfireAuthenticateEv2.authenticateAesEv2First(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_AES_DEFAULT);
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString2 + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SES_AUTH_ENC_KEY = desfireAuthenticateEv2.getSesAuthENCKey();
                    SES_AUTH_MAC_KEY = desfireAuthenticateEv2.getSesAuthMACKey();
                    TRANSACTION_IDENTIFIER = desfireAuthenticateEv2.getTransactionIdentifier();
                    CMD_COUNTER = desfireAuthenticateEv2.getCmdCounter();
                    writeToUiAppend(output, printData("SES_AUTH_ENC_KEY", SES_AUTH_ENC_KEY));
                    writeToUiAppend(output, printData("SES_AUTH_MAC_KEY", SES_AUTH_MAC_KEY));
                    writeToUiAppend(output, printData("TRANSACTION_IDENTIFIER", TRANSACTION_IDENTIFIER));
                    writeToUiAppend(output, "CMD_COUNTER: " + CMD_COUNTER);
                    vibrateShort();
                    // show logData
/*
                    // prepare data for export
                    exportString = desfireAuthenticateEv2.getLogData();
                    exportStringFileName = "auth0a_ev2.html";
                    writeToUiToast("your authentication log file is ready for export");
*/
                    //showDialog(MainActivity.this, desfireAuthenticateProximity.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString2 + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                }

                /*
                // run a test
                boolean testSuccess = desfireAuthenticateEv2.changeFileSettingsSdmEv2Test();
                if (testSuccess) {
                    writeToUiAppend(output, "changeFileSettingsSdmEv2Test SUCCESS");
                } else {
                    writeToUiAppend(output, "changeFileSettingsSdmEv2Test FAILURE");
                }
                */

                // get the existing file settings
                // we need the MACed execution to run this command
                writeToUiAppend(output, logString + " step 3: get the existing fileSettingsMac SDM");
                byte[] fileSettingsLoad = desfireAuthenticateEv2.getFileSettingsMacEv2(ndefFileId);
                writeToUiAppend(output, printData("fileSettings", fileSettingsLoad));
                if ((fileSettingsLoad == null) || (fileSettingsLoad.length < 6)) {
                    writeToUiAppend(output, "Error on reading fileSettings, aborted");
                    return;
                }
                FileSettings fs = new FileSettings(ndefFileId, fileSettingsLoad);
                if (fs != null) {
                    writeToUiAppend(output, fs.dump());
                }
                writeToUiAppend(output, logString + " step 4: change the fileSettings SDM");
                success = desfireAuthenticateEv2.changeFileSettingsSdmEv2(ndefFileId);
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a ?? ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error: " + EV3.getErrorCode(responseData), COLOR_RED);
                    return;
                }
            }
        });

        sdmTestFileSettingsEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "SDM testFileSettings";
                writeToUiAppend(output, logString);

                // this is only testing the FileSettings class when input is SDM enriched data
                // typical getFileSettings respond 00 40 00 E0 00 01 00 C1 F1 21 20 00 00 43 00 00 43 00 00 (19 bytes)
                // response from NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf, page 21
                // response from 0040EEEE000100D1FE001F00004400004400002000006A0000

                byte[] fileSettingsStandardResponse = Utils.hexStringToByteArray("0003301F000100"); // Standard file: FileType || FileOption || AccessRights || FileSize
                byte[] fileSettingsSdmResponse = Utils.hexStringToByteArray("004000E0000100C1F121200000430000430000");
                //byte[] fileSettingsSdm424Response = Utils.hexStringToByteArray("0040EEEE000100D1FE001F00004400004400002000006A0000");
                byte[] fileSettingsSdm424Response = Utils.hexStringToByteArray("004000E0000100F12121200000430000430000");
/*
40h = FileOption (SDM and
Mirroring enabled), CommMode: plain
00E0h = AccessRights (FileAR.ReadWrite: 0x0, FileAR.Change: 0x0, FileAR.Read: 0xE, FileAR.Write; 0x0)
C1h =
• UID mirror: 1
• SDMReadCtr: 1
• SDMReadCtrLimit: 0
• SDMENCFileData: 0
• ASCII Encoding mode: 1
• F121h = SDMAccessRights (RFU: 0xF, FileAR.SDMCtrRet = 0x1, FileAR.SDMMetaRead: 0x2, FileAR.SDMFileRead: 0x1)
• 200000h = ENCPICCDataOffset
• 430000h = SDMMACOffset
• 430000h = SDMMACInputOffset
*/
                byte fileNumber = (byte) 0x01;
                FileSettings fileSettingsStandard = new FileSettings(fileNumber, fileSettingsStandardResponse);
                writeToUiAppend(output, fileSettingsStandard.dump());
                fileNumber = (byte) 0x02;
                FileSettings fileSettingsSdm = new FileSettings(fileNumber, fileSettingsSdmResponse);
                writeToUiAppend(output, fileSettingsSdm.dump());
                fileNumber = (byte) 0x03;
                FileSettings fileSettingsSdm424 = new FileSettings(fileNumber, fileSettingsSdm424Response);
                writeToUiAppend(output, fileSettingsSdm424.dump());
            }
        });

        sdmGetFileSettingsEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "SDM getFileSettings";
                writeToUiAppend(output, logString);
                byte[] ndefApplication = hexStringToByteArray("010000"); // the AID is 00 00 01 but data is in low endian

                // this is when using TapLinx formatT4T NDEF files
                //byte[] ndefApplication = hexStringToByteArray("115427"); // used by TapLinx formatT4T

                byte ndefFileId = (byte) 0x02;
                writeToUiAppend(output, "fileNumber (fixed): " + ndefFileId + printData(" ndefApplication", ndefApplication));

                byte[] responseData = new byte[2];
                writeToUiAppend(output, logString + " step 1: select ndef application");
                // select the application
                //boolean success = desfireAuthenticateLegacy.selectApplication(ndefApplication);
                //responseData = desfireAuthenticateLegacy.getErrorCode();
                boolean success = desfireAuthenticateEv2.selectApplicationByAidEv2(ndefApplication);
                responseData = desfireAuthenticateEv2.getErrorCode();
                if (success) {
                    writeToUiAppend(output, "select the application SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "select the application SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "select the application FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                }
/*
                // don't forget to run an auth to get a SessionKey
                String logString2 = "step 2: EV2 First authenticate with DEFAULT AES key number 0x00 = application master key";
                writeToUiAppend(output, logString2);

                exportString = "";
                exportStringFileName = "auth.html";

                success = desfireAuthenticateEv2.authenticateAesEv2First(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_AES_DEFAULT);
                //success = desfireAuthenticateEv2.authenticateAesEv2First(APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_MASTER_AES_DEFAULT);
                //success = desfireAuthenticateEv2.authenticateAesEv2First(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_MASTER_AES_DEFAULT);

                responseData = desfireAuthenticateEv2.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString2 + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SES_AUTH_ENC_KEY = desfireAuthenticateEv2.getSesAuthENCKey();
                    SES_AUTH_MAC_KEY = desfireAuthenticateEv2.getSesAuthMACKey();
                    TRANSACTION_IDENTIFIER = desfireAuthenticateEv2.getTransactionIdentifier();
                    CMD_COUNTER = desfireAuthenticateEv2.getCmdCounter();
                    writeToUiAppend(output, printData("SES_AUTH_ENC_KEY", SES_AUTH_ENC_KEY));
                    writeToUiAppend(output, printData("SES_AUTH_MAC_KEY", SES_AUTH_MAC_KEY));
                    writeToUiAppend(output, printData("TRANSACTION_IDENTIFIER", TRANSACTION_IDENTIFIER));
                    writeToUiAppend(output, "CMD_COUNTER: " + CMD_COUNTER);
                    vibrateShort();
                    // show logData
                    //showDialog(MainActivity.this, desfireAuthenticateProximity.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString2 + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
*/
                // TapLinx formatT4T is using DES application keys
                /*
                boolean suc = desfireAuthenticateLegacy.authenticateD40(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_DES_DEFAULT);
                if (suc) {
                    writeToUiAppend(output, "Auth SUCCESS");
                } else {
                    writeToUiAppend(output, "Auth FAILURE");
                    return;
                }
                */

                writeToUiAppend(output, logString + " step 3: get the fileSettings");
                byte[] response = desfireAuthenticateEv2.getFileSettingsEv2(ndefFileId);
                responseData = desfireAuthenticateEv2.getErrorCode();
                writeToUiAppend(output, printData("response", response));
                if (checkResponse(responseData)) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    FileSettings fileSettings = new FileSettings(ndefFileId, response);
                    writeToUiAppend(output, fileSettings.dump());

                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a ?? ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error: " + EV3.getErrorCode(responseData), COLOR_RED);
                    return;
                }


            }
        });

        sdmDecryptNdefManualEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "SDM decryptNdefManual EV2";
                writeToUiAppend(output, logString);

                // empty template
                // String ndefSampleUrl = "https://choose.aburl.com/ntag424?e=00000000000000000000000000000000&c=0000000000000000";

                // this is static data
                byte[] iv = new byte[16]; // default AES iv
                byte[] key = new byte[16]; // default AES key
                byte[] encryptedNdefData = hexStringToByteArray("9AE19A07072580D459A4A920FA5A7842");
                // SDM decryptNdefManual EV2 decryptedNdefData length: 16 data: c7045140325014900500001f8c94e251
                // piccDataTag: C7
                // uid length: 7 data: 04514032501490
                // readCtr length: 3 data: 050000
                // randomPadding length: 5 data: 1f8c94e251

                /*
                // sample data from Features & Hints
                byte[] encryptedNdefDataSample = hexStringToByteArray("EF963FF7828658A599F3041510671E88");
                byte[] decryptedNdefDataSampleExpected = hexStringToByteArray("C704DE5F1EACC0403D0000DA5CF60941");
                // encrypted EF963FF7828658A599F3041510671E88
                // decrypted C704DE5F1EACC0403D0000DA5CF60941

                byte[] decryptedNdefDataSample = desfireAuthenticateEv2.decryptNdefDataEv2(iv, key, encryptedNdefDataSample);
                if (decryptedNdefDataSample != null) {
                    writeToUiAppend(output, logString +  printData(" decryptedNdefDataSample", decryptedNdefDataSample));
                    writeToUiAppend(output, logString +  printData(" decryptedNdefData Expct", decryptedNdefDataSampleExpected));
                    writeToUiAppend(output, "decryption success: " + Arrays.equals(decryptedNdefDataSample, decryptedNdefDataSampleExpected));
                } else {
                    writeToUiAppend(output, logString + " decryptedNdefDataSample is NULL");
                }
                writeToUiAppend(output, "now decrypting tag data");
                */
                byte[] decryptedNdefData = desfireAuthenticateEv2.decryptNdefDataEv2(iv, key, encryptedNdefData);
                byte[] uid = new byte[0];
                byte[] readCtr = new byte[0];
                if (decryptedNdefData != null) {
                    writeToUiAppend(output, logString + printData(" decryptedNdefData", decryptedNdefData));
                    // split encrypted PICC data from NDEF / SDM
                    byte piccDataTag = decryptedNdefData[0];
                    uid = Arrays.copyOfRange(decryptedNdefData, 1, 8);
                    readCtr = Arrays.copyOfRange(decryptedNdefData, 8, 11);
                    byte[] randomPadding = Arrays.copyOfRange(decryptedNdefData, 11, 16);
                    writeToUiAppend(output, "piccDataTag: " + byteToHex(piccDataTag));
                    writeToUiAppend(output, printData("uid", uid));
                    writeToUiAppend(output, printData("readCtr", readCtr));
                    writeToUiAppend(output, printData("randomPadding", randomPadding));

                } else {
                    writeToUiAppend(output, logString + " decryptedNdefData is NULL");
                }

                writeToUiAppend(output, "now verifying the MAC");
                byte[] sdmFileReadKey = new byte[16]; // default AES key // is set to key 1 in TapLinx

/*
                // sample data
                byte[] uidSample = hexStringToByteArray("04DE5F1EACC040");
                byte[] readCtrSample = hexStringToByteArray("3D0000");
                byte[] sesSDMFileReadMACKeySampleExpected = hexStringToByteArray("3FB5F6E3A807A03D5E3570ACE393776F");
                byte[] sesSDMFileReadMACKeySample = desfireAuthenticateEv2.getSesSDMFileReadMACKey(sdmFileReadKey, uidSample, readCtrSample);
                writeToUiAppend(output, printData("sesSDMFileReadMACKeySample", sesSDMFileReadMACKeySample));
                writeToUiAppend(output, printData("sesSDMFileReadMACKeySamExp", sesSDMFileReadMACKeySampleExpected));
                writeToUiAppend(output, "The sesSDMFileReadMACKeySample is equals to the expected value: " + Arrays.equals(sesSDMFileReadMACKeySample, sesSDMFileReadMACKeySampleExpected));
                byte[] sdmMacSample = desfireAuthenticateEv2.getSdmMac(sesSDMFileReadMACKeySample);
                writeToUiAppend(output, printData("sdmMacSample", sdmMacSample));
                // now truncate the MAC
                byte[] sdmMacTruncatedSample = desfireAuthenticateEv2.truncateMAC(sdmMacSample);
                byte[] sdmMacSampleExpected = hexStringToByteArray("94EED9EE65337086");
                writeToUiAppend(output, printData("sdmMacTruncateSample", sdmMacTruncatedSample));
                writeToUiAppend(output, printData("sdmMacSampleExpected", sdmMacSampleExpected));
                writeToUiAppend(output, "The sdmMacTruncateSample is equals to the expected value: " + Arrays.equals(sdmMacTruncatedSample, sdmMacSampleExpected));
*/
                // read data
                writeToUiAppend(output, "MAC - working with real data");
                byte[] macData = hexStringToByteArray("6AE1C36FEB5721D2");
                writeToUiAppend(output, printData("macData from NDEF", macData));
                byte[] sesSDMFileReadMACKey = desfireAuthenticateEv2.getSesSDMFileReadMACKey(sdmFileReadKey, uid, readCtr);
                writeToUiAppend(output, printData("sesSDMFileReadMACKey", sesSDMFileReadMACKey));
                byte[] sdmMac = desfireAuthenticateEv2.getSdmMac(sesSDMFileReadMACKey);
                writeToUiAppend(output, printData("sdmMac", sdmMac));
                // now truncate the MAC
                byte[] sdmMacTruncated = desfireAuthenticateEv2.truncateMAC(sdmMac);
                writeToUiAppend(output, printData("sdmMacTruncated", sdmMacTruncated));
                writeToUiAppend(output, "The sdmMac matches macData value: " + Arrays.equals(macData, sdmMacTruncated));
            }
        });


    }

    /**
     * section for application handling
     */

    private boolean createApplicationPlainCommunicationDes(TextView logTextView, byte[] applicationIdentifier, byte numberOfKeys, byte[] methodResponse) {
        final String methodName = "createApplicationPlainCommunicationDes";
        Log.d(TAG, methodName);
        // sanity checks
        if (logTextView == null) {
            Log.e(TAG, methodName + " logTextView is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (applicationIdentifier == null) {
            Log.e(TAG, methodName + " applicationIdentifier is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (applicationIdentifier.length != 3) {
            Log.e(TAG, methodName + " applicationIdentifier length is not 3, found: " + applicationIdentifier.length + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (numberOfKeys < 1) {
            Log.e(TAG, methodName + " numberOfKeys is < 1, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (numberOfKeys > 14) {
            Log.e(TAG, methodName + " numberOfKeys is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            writeToUiAppend(logTextView, methodName + " lost connection to the card, aborted");
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        // generate the parameter
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(applicationIdentifier, 0, 3);
        baos.write(APPLICATION_MASTER_KEY_SETTINGS);
        baos.write(numberOfKeys);
        byte[] parameter = baos.toByteArray();
        Log.d(TAG, methodName + printData(" parameter", parameter));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(CREATE_APPLICATION_COMMAND, parameter);
            Log.d(TAG, methodName + printData(" apdu", apdu));
            // sample: 90ca000005d0d1d20f0500
            //       0x90CA000005D1D2D30F0500
            response = isoDep.transceive(apdu);
            Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, methodResponse, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }
    }

    private boolean createApplicationPlainCommunicationAes(TextView logTextView, byte[] applicationIdentifier, byte numberOfKeys, byte[] methodResponse) {
        final String methodName = "createApplicationPlainCommunicationDes";
        Log.d(TAG, methodName);
        // sanity checks
        if (logTextView == null) {
            Log.e(TAG, methodName + " logTextView is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (applicationIdentifier == null) {
            Log.e(TAG, methodName + " applicationIdentifier is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (applicationIdentifier.length != 3) {
            Log.e(TAG, methodName + " applicationIdentifier length is not 3, found: " + applicationIdentifier.length + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (numberOfKeys < 1) {
            Log.e(TAG, methodName + " numberOfKeys is < 1, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (numberOfKeys > 14) {
            Log.e(TAG, methodName + " numberOfKeys is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            writeToUiAppend(logTextView, methodName + " lost connection to the card, aborted");
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        // generate the parameter
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(applicationIdentifier, 0, 3);
        baos.write(APPLICATION_MASTER_KEY_SETTINGS);
        baos.write(numberOfKeys | APPLICATION_CRYPTO_AES); // here we decide if the application is DES or AES
        byte[] parameter = baos.toByteArray();
        Log.d(TAG, methodName + printData(" parameter", parameter));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(CREATE_APPLICATION_COMMAND, parameter);
            Log.d(TAG, methodName + printData(" apdu", apdu));
            response = isoDep.transceive(apdu);
            Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, methodResponse, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }
    }

    /**
     * section for file handling
     */

    private boolean createStandardFilePlainCommunicationDes(TextView logTextView, byte fileNumber, int fileSize, boolean isFreeAccess, byte[] methodResponse) {
        final String methodName = "createFilePlainCommunicationDes";
        Log.d(TAG, methodName);
        // sanity checks
        if (logTextView == null) {
            Log.e(TAG, methodName + " logTextView is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (fileNumber < 0) {
            Log.e(TAG, methodName + " fileNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (fileNumber > 14) {
            Log.e(TAG, methodName + " fileNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (fileSize < 1) {
            Log.e(TAG, methodName + " fileSize is < 1, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (fileSize > MAXIMUM_FILE_SIZE) {
            Log.e(TAG, methodName + " fileSize is > " + MAXIMUM_FILE_SIZE + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            writeToUiAppend(logTextView, methodName + " lost connection to the card, aborted");
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (isFreeAccess) {
            Log.d(TAG, methodName + " file is created with FREE access");
        } else {
            Log.d(TAG, methodName + " file is created with KEY SECURED access");
        }
        byte[] fileSizeArray = Utils.intTo3ByteArrayInversed(fileSize); // lsb order
        // generate the parameter
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(FILE_COMMUNICATION_SETTINGS);
        // the access rights depend on free access or not
        if (isFreeAccess) {
            baos.write(ACCESS_RIGHTS_RW_CAR_FREE);
            baos.write(ACCESS_RIGHTS_R_W_FREE);
        } else {
            baos.write(ACCESS_RIGHTS_RW_CAR_SECURED);
            baos.write(ACCESS_RIGHTS_R_W_SECURED);
        }
        baos.write(fileSizeArray, 0, 3);
        byte[] parameter = baos.toByteArray();
        Log.d(TAG, methodName + printData(" parameter", parameter));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(CREATE_STANDARD_FILE_COMMAND, parameter);
            Log.d(TAG, methodName + printData(" apdu", apdu));
            // sample free access: 90cd0000070000eeee20000000 (13 bytes)
            // sample key secured: 90cd0000070100123420000000 (13 bytes)
            response = isoDep.transceive(apdu);
            Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, methodResponse, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }
    }

    private byte[] readFromAStandardFilePlainCommunicationDes(TextView logTextView, byte fileNumber, int fileSize, byte[] methodResponse) {
        final String methodName = "readStandardFilePlainCommunicationDes";
        Log.d(TAG, methodName);
        // sanity checks
        if (logTextView == null) {
            Log.e(TAG, methodName + " logTextView is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        if (fileNumber < 0) {
            Log.e(TAG, methodName + " fileNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        if (fileNumber > 14) {
            Log.e(TAG, methodName + " fileNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        if ((fileSize < 0) || (fileSize > MAXIMUM_FILE_SIZE)) {
            Log.e(TAG, methodName + " fileSize has to be in range 0.." + MAXIMUM_FILE_SIZE + " but found " + fileSize + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            writeToUiAppend(logTextView, methodName + " lost connection to the card, aborted");
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        // generate the parameter
        int offsetBytes = 0; // read from the beginning
        byte[] offset = Utils.intTo3ByteArrayInversed(offsetBytes); // LSB order
        byte[] length = Utils.intTo3ByteArrayInversed(fileSize); // LSB order
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(offset, 0, 3);
        baos.write(length, 0, 3);
        byte[] parameter = baos.toByteArray();
        Log.d(TAG, methodName + printData(" parameter", parameter));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(READ_STANDARD_FILE_COMMAND, parameter);
            Log.d(TAG, methodName + printData(" apdu", apdu));
            // sample: 90bd0000070000000020000000 (13 bytes)
            //       0x903D00002400000000000000
            response = isoDep.transceive(apdu);
            Log.d(TAG, methodName + printData(" response", response));
            // sample: 323032332e30372e32312031373a30343a3034203132333435363738393031329100 (34 bytes)
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, methodResponse, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");

            /*
            // for AES only - update the global IV
            // status NOT working
            // todo this is just for testing the IV "update" when getting the cardUid on AES
            byte[] cmacIv = calculateApduCMAC(apdu, SESSION_KEY_AES, IV.clone());
            writeToUiAppend(output, printData("cmacIv", cmacIv));
            IV = cmacIv.clone();
             */

            // now strip of the response bytes
            // if the card responses more data than expected we truncate the data
            int expectedResponse = fileSize - offsetBytes;
            if (response.length == expectedResponse) {
                return response;
            } else if (response.length > expectedResponse) {
                // more data is provided - truncated
                return Arrays.copyOf(response, expectedResponse);
            } else {
                // less data is provided - we return as much as possible
                return response;
            }
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
    }

    public byte[] getModifiedKey(byte[] key) {
        String methodName = "getModifiedKey";
        Log.d(TAG, methodName + printData(" key", key));
        if ((key == null) || (key.length != 8)) {
            Log.d(TAG, methodName + " Error: key is NULL or key length is not of 8 bytes length, aborted");
            return null;
        }
        byte[] modifiedKey = new byte[24];
        System.arraycopy(key, 0, modifiedKey, 16, 8);
        System.arraycopy(key, 0, modifiedKey, 8, 8);
        System.arraycopy(key, 0, modifiedKey, 0, key.length);
        Log.d(TAG, methodName + printData(" modifiedKey", modifiedKey));
        return modifiedKey;
    }

    // this is the code as readFromAStandardFilePlainCommunicationDes but we allow a fileNumber 15 (0x0F) for TMAC files
    private byte[] readFromAStandardFilePlainCommunication(TextView logTextView, byte fileNumber, int fileSize, byte[] methodResponse) {
        final String methodName = "createFilePlainCommunication";
        Log.d(TAG, methodName);
        // sanity checks
        if (logTextView == null) {
            Log.e(TAG, methodName + " logTextView is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        if (fileNumber < 0) {
            Log.e(TAG, methodName + " fileNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        if (fileNumber > 15) {
            Log.e(TAG, methodName + " fileNumber is > 15, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        /*
        if ((fileSize < 1) || (fileSize > MAXIMUM_FILE_SIZE)) {
            Log.e(TAG, methodName + " fileSize has to be in range 1.." + MAXIMUM_FILE_SIZE + " but found " + fileSize + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }

         */
        if ((isoDep == null) || (!isoDep.isConnected())) {
            writeToUiAppend(logTextView, methodName + " lost connection to the card, aborted");
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        // generate the parameter
        int offsetBytes = 0; // read from the beginning
        byte[] offset = Utils.intTo3ByteArrayInversed(offsetBytes); // LSB order
        byte[] length = Utils.intTo3ByteArrayInversed(fileSize); // LSB order
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(offset, 0, 3);
        baos.write(length, 0, 3);
        byte[] parameter = baos.toByteArray();
        Log.d(TAG, methodName + printData(" parameter", parameter));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(READ_STANDARD_FILE_COMMAND, parameter);
            Log.d(TAG, methodName + printData(" apdu", apdu));
            response = isoDep.transceive(apdu);
            Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, methodResponse, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            // now strip of the response bytes
            // if the card responses more data than expected we truncate the data
            int expectedResponse = fileSize - offsetBytes;
            if (response.length == expectedResponse) {
                return response;
            } else if (response.length > expectedResponse) {
                // more data is provided - truncated
                return Arrays.copyOf(response, expectedResponse);
            } else {
                // less data is provided - we return as much as possible
                return response;
            }
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
    }

    private boolean writeToAStandardFilePlainCommunicationDes(TextView logTextView, byte fileNumber, byte[] data, byte[] methodResponse) {
        final String methodName = "writeToAStandardFilePlainCommunicationDes";
        Log.d(TAG, methodName);
        // sanity checks
        if (logTextView == null) {
            Log.e(TAG, methodName + " logTextView is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (fileNumber < 0) {
            Log.e(TAG, methodName + " fileNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (fileNumber > 14) {
            Log.e(TAG, methodName + " fileNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if ((data == null) || (data.length < 1) || (data.length > selectedFileSize)) {
            Log.e(TAG, "data length not in range 1.." + MAXIMUM_FILE_SIZE + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            writeToUiAppend(logTextView, methodName + " lost connection to the card, aborted");
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        // generate the parameter
        int numberOfBytes = data.length;
        int offsetBytes = 0; // write from the beginning
        byte[] offset = Utils.intTo3ByteArrayInversed(offsetBytes); // LSB order
        byte[] length = Utils.intTo3ByteArrayInversed(numberOfBytes); // LSB order
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(offset, 0, 3);
        baos.write(length, 0, 3);
        baos.write(data, 0, numberOfBytes);
        byte[] parameter = baos.toByteArray();
        Log.d(TAG, methodName + printData(" parameter", parameter));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(WRITE_STANDARD_FILE_COMMAND, parameter);
            Log.d(TAG, methodName + printData(" apdu", apdu));
            // sample:  903d00002700000000200000323032332e30372e32312031373a30343a30342031323334353637383930313200 (45 bytes)
            response = isoDep.transceive(apdu);
            Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, methodResponse, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            return false;
        }
    }

    public byte[] getFileSettingsA(TextView logTextView, byte fileNumber, byte[] methodResponse) {
        final String methodName = "getFileSettings";
        Log.d(TAG, methodName);
        // sanity checks
        if (logTextView == null) {
            Log.e(TAG, methodName + " logTextView is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        if (fileNumber < 0) {
            Log.e(TAG, methodName + " fileNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        if (fileNumber > 14) {
            Log.e(TAG, methodName + " fileNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        // generate the parameter
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        byte[] parameter = baos.toByteArray();
        Log.d(TAG, methodName + printData(" parameter", parameter));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(GET_FILE_SETTINGS_COMMAND, parameter);
            Log.d(TAG, methodName + printData(" apdu", apdu));
            response = isoDep.transceive(apdu);
            Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, methodResponse, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
    }


    private boolean changeFileSettingsA(TextView logTextView, byte fileNumber, byte[] methodResponse) {
        // NOTE: don't forget to authenticate with CAR key

        if (SESSION_KEY_DES == null) {
            writeToUiAppend(logTextView, "the SESSION KEY DES is null, did you forget to authenticate with a CAR key first ?");
            return false;
        }

        int selectedFileIdInt = Integer.parseInt(selectedFileId);
        byte selectedFileIdByte = Byte.parseByte(selectedFileId);
        Log.d(TAG, "changeTheFileSettings for selectedFileId " + selectedFileIdInt);
        Log.d(TAG, printData("DES session key", SESSION_KEY_DES));

        // CD | File No | Comms setting byte | Access rights (2 bytes) | File size (3 bytes)
        byte commSettingsByte = 0; // plain communication without any encryption

        // we are changing the keys for R and W from 0x34 to 0x22;
        byte accessRightsRwCar = (byte) 0x12; // Read&Write Access & ChangeAccessRights
        //byte accessRightsRW = (byte) 0x34; // Read Access & Write Access // read with key 3, write with key 4
        byte accessRightsRW = (byte) 0x22; // Read Access & Write Access // read with key 2, write with key 2
        // to calculate the crc16 over the setting bytes we need a 3 byte long array
        byte[] bytesForCrc = new byte[3];
        bytesForCrc[0] = commSettingsByte;
        bytesForCrc[1] = accessRightsRwCar;
        bytesForCrc[2] = accessRightsRW;
        Log.d(TAG, printData("bytesForCrc", bytesForCrc));
        byte[] crc16Value = CRC16.get(bytesForCrc);
        Log.d(TAG, printData("crc16Value", crc16Value));
        // create a 8 byte long array
        byte[] bytesForDecryption = new byte[8];
        System.arraycopy(bytesForCrc, 0, bytesForDecryption, 0, 3);
        System.arraycopy(crc16Value, 0, bytesForDecryption, 3, 2);
        Log.d(TAG, printData("bytesForDecryption", bytesForDecryption));
        // generate 24 bytes long triple des key
        byte[] tripleDES_SESSION_KEY = getModifiedKey(SESSION_KEY_DES);
        Log.d(TAG, printData("tripleDES Session Key", tripleDES_SESSION_KEY));
        byte[] IV_DES = new byte[8];
        Log.d(TAG, printData("IV_DES", IV_DES));
        byte[] decryptedData = TripleDES.decrypt(IV_DES, tripleDES_SESSION_KEY, bytesForDecryption);
        Log.d(TAG, printData("decryptedData", decryptedData));
        // the parameter for wrapping
        byte[] parameter = new byte[9];
        parameter[0] = selectedFileIdByte;
        System.arraycopy(decryptedData, 0, parameter, 1, 8);
        Log.d(TAG, printData("parameter", parameter));
        byte[] wrappedCommand;
        byte[] response;
        try {
            wrappedCommand = wrapMessage(CHANGE_FILE_SETTINGS_COMMAND, parameter);
            Log.d(TAG, printData("wrappedCommand", wrappedCommand));
            response = isoDep.transceive(wrappedCommand);
            Log.d(TAG, printData("response", response));
            System.arraycopy(response, 0, methodResponse, 0, 2);
            if (checkResponse(response)) {
                return true;
            } else {
                return false;
            }
        } catch (IOException e) {
            writeToUiAppend(output, "IOException: " + e.getMessage());
            e.printStackTrace();
        }
        return false;
    }

    /**
     * section for key handling
     */


    /**
     * section for general handling
     */

    private byte[] getCardUid(TextView logTextView, byte[] methodResponse) {
        final String methodName = "getCardUid";
        Log.d(TAG, methodName);
        // sanity checks
        if (logTextView == null) {
            Log.e(TAG, methodName + " logTextView is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        // no parameter
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(GET_CARD_UID_COMMAND, null);
            Log.d(TAG, methodName + printData(" apdu", apdu));
            response = isoDep.transceive(apdu);
            Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, methodResponse, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
    }


    /**
     * copied from DESFireEV1.java class
     * necessary for calculation the new IV for decryption of getCardUid
     *
     * @param apdu
     * @param sessionKey
     * @param iv
     * @return
     */
    private byte[] calculateApduCMAC(byte[] apdu, byte[] sessionKey, byte[] iv) {
        Log.d(TAG, "calculateApduCMAC" + printData(" apdu", apdu) +
                printData(" sessionKey", sessionKey) + printData(" iv", iv));
        byte[] block;

        if (apdu.length == 5) {
            block = new byte[apdu.length - 4];
        } else {
            // trailing 00h exists
            block = new byte[apdu.length - 5];
            System.arraycopy(apdu, 5, block, 1, apdu.length - 6);
        }
        block[0] = apdu[1];
        Log.d(TAG, "calculateApduCMAC" + printData(" block", block));
        //byte[] newIv = desfireAuthenticateProximity.calculateDiverseKey(sessionKey, iv);
        //return newIv;
        byte[] cmacIv = CMAC.get(CMAC.Type.AES, sessionKey, block, iv);
        Log.d(TAG, "calculateApduCMAC" + printData(" cmacIv", cmacIv));
        return cmacIv;
    }

    private static byte[] calculateApduCRC32R(byte[] apdu, int length) {
        byte[] data = new byte[length + 1];
        System.arraycopy(apdu, 0, data, 0, length);// response code is at the end
        return CRC32.get(data);
    }


    /**
     * section for command and response handling
     */

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

    private byte[] returnStatusBytes(byte[] data) {
        return Arrays.copyOfRange(data, (data.length - 2), data.length);
    }

    /**
     * checks if the response has an 0x'9100' at the end means success
     * and the method returns the data without 0x'9100' at the end
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return
     */
    private boolean checkResponse(byte[] data) {
        if (data == null) return false;
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        if (Arrays.equals(RESPONSE_OK, returnStatusBytes(data))) {
            return true;
        } else {
            return false;
        }
        /*
        int status = ((0xff & data[data.length - 2]) << 8) | (0xff & data[data.length - 1]);
        if (status == 0x9100) {
            return true;
        } else {
            return false;
        }
         */
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
        /*
        int status = ((0xff & data[data.length - 2]) << 8) | (0xff & data[data.length - 1]);
        if (status == 0x91AF) {
            return true;
        } else {
            return false;
        }
         */
    }

    /**
     * checks if the response has an 0x'91AE' at the end means
     * that an authentication with an appropriate key is missing
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return
     */
    private boolean checkAuthenticationError(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        if (Arrays.equals(RESPONSE_AUTHENTICATION_ERROR, returnStatusBytes(data))) {
            return true;
        } else {
            return false;
        }
        /*
        int status = ((0xff & data[data.length - 2]) << 8) | (0xff & data[data.length - 1]);
        if (status == 0x91AE) {
            return true;
        } else {
            return false;
        }
         */
    }

    /**
     * section for NFC handling
     */

    // This method is run in another thread when a card is discovered
    // !!!! This method cannot cannot direct interact with the UI Thread
    // Use `runOnUiThread` method to change the UI from this method
    @Override
    public void onTagDiscovered(Tag tag) {

        clearOutputFields();
        invalidateAllSelections();
        writeToUiAppend(output, "NFC tag discovered");

        ntag424DnaMethods = new Ntag424DnaMethods(output, tag, activity);

/*
        isoDep = null;
        try {
            isoDep = IsoDep.get(tag);
            if (isoDep != null) {
                // Make a Vibration
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(150, 10));
                } else {
                    Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
                    v.vibrate(200);
                }

                runOnUiThread(() -> {
                    output.setText("");
                    errorCode.setText("");
                    errorCode.setBackgroundColor(getResources().getColor(R.color.white));
                });
                isoDep.connect();
                if (!isoDep.isConnected()) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "could not connect to the tag, aborted", COLOR_RED);
                    isoDep.close();
                    return;
                }
                desfireAuthenticate = new DesfireAuthenticate(isoDep, true); // true means all data is logged

                //desfireAuthenticateProximity = new DesfireAuthenticateProximity(isoDep, true); // true means all data is logged
                desfireAuthenticateLegacy = new DesfireAuthenticateLegacy(isoDep, true); // true means all data is logged
                desfireAuthenticateEv2 = new DesfireAuthenticateEv2(isoDep, true); // true means all data is logged

                // setup the communication adapter
                //adapter = new CommunicationAdapter(isoDep, true);

                // get tag ID
                tagIdByte = tag.getId();
                writeToUiAppend(output, "tag id: " + Utils.bytesToHex(tagIdByte));
                Log.d(TAG, "tag id: " + Utils.bytesToHex(tagIdByte));

                writeToUiAppend(output, "NFC tag connected");
                writeToUiAppendBorderColor(errorCode, errorCodeLayout, "The app and DESFire tag are ready to use", COLOR_GREEN);
            }

        } catch (IOException e) {
            writeToUiAppend(output, "ERROR: IOException " + e.getMessage());
            writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
            e.printStackTrace();
        } catch (Exception e) {
            writeToUiAppend(output, "ERROR: Exception " + e.getMessage());
            writeToUiAppendBorderColor(errorCode, errorCodeLayout, "Exception: " + e.getMessage(), COLOR_RED);
            e.printStackTrace();
        }
*/
    }

    @Override
    protected void onResume() {
        super.onResume();

        if (mNfcAdapter != null) {

            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            // Enable ReaderMode for all types of card and disable platform sounds
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is NOT set
            // to get the data of the tag afer reading
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_NFC_BARCODE |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null) {
            mNfcAdapter.disableReaderMode(this);
        }
    }


    /**
     * section for layout handling
     */
    private void allLayoutsInvisible() {
        //llApplicationHandling.setVisibility(View.GONE);
        //llStandardFile.setVisibility(View.GONE);
    }

    /**
     * section for UI handling
     */

    private void writeToUiAppend(TextView textView, String message) {
        runOnUiThread(() -> {
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

    private void writeToUiAppendBorderColor(TextView textView, TextInputLayout textInputLayout, String message, int color) {
        runOnUiThread(() -> {

            // set the color to green
            //Color from rgb
            // int color = Color.rgb(255,0,0); // red
            //int color = Color.rgb(0,255,0); // green
            //Color from hex string
            //int color2 = Color.parseColor("#FF11AA"); light blue
            int[][] states = new int[][]{
                    new int[]{android.R.attr.state_focused}, // focused
                    new int[]{android.R.attr.state_hovered}, // hovered
                    new int[]{android.R.attr.state_enabled}, // enabled
                    new int[]{}  //
            };
            int[] colors = new int[]{
                    color,
                    color,
                    color,
                    //color2
                    color
            };
            ColorStateList myColorList = new ColorStateList(states, colors);
            textInputLayout.setBoxStrokeColorStateList(myColorList);

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

    private void writeToUiToast(String message) {
        runOnUiThread(() -> {
            Toast.makeText(getApplicationContext(),
                    message,
                    Toast.LENGTH_SHORT).show();
        });
    }

    private void clearOutputFields() {
        runOnUiThread(() -> {
            output.setText("");
            errorCode.setText("");
        });
        // reset the border color to primary for errorCode
        int color = R.color.colorPrimary;
        int[][] states = new int[][]{
                new int[]{android.R.attr.state_focused}, // focused
                new int[]{android.R.attr.state_hovered}, // hovered
                new int[]{android.R.attr.state_enabled}, // enabled
                new int[]{}  //
        };
        int[] colors = new int[]{
                color,
                color,
                color,
                color
        };
        ColorStateList myColorList = new ColorStateList(states, colors);
        errorCodeLayout.setBoxStrokeColorStateList(myColorList);
    }

    private void invalidateAllSelections() {
        selectedApplicationId = null;
        selectedFileId = "";
        runOnUiThread(() -> {
            applicationSelected.setText("");
            fileSelected.setText("");
        });
        KEY_NUMBER_USED_FOR_AUTHENTICATION = -1;
        SESSION_KEY_DES = null;
        SESSION_KEY_TDES = null;
    }

    private void invalidateEncryptionKeys() {
        KEY_NUMBER_USED_FOR_AUTHENTICATION = -1;
        SESSION_KEY_DES = null;
        SESSION_KEY_TDES = null;
    }

    private void vibrateShort() {
        // Make a Sound
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(50, 10));
        } else {
            Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
            v.vibrate(50);
        }
    }

    /**
     * section OptionsMenu export text file methods
     */

    private void exportTextFile() {
        //provideTextViewDataForExport(etLog);
        if (TextUtils.isEmpty(exportString)) {
            writeToUiToast("Log some data before writing files :-)");
            return;
        }
        writeStringToExternalSharedStorage();
    }

    private void writeStringToExternalSharedStorage() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        // Optionally, specify a URI for the file that should appear in the
        // system file picker when it loads.
        // boolean pickerInitialUri = false;
        // intent.putExtra(DocumentsContract.EXTRA_INITIAL_URI, pickerInitialUri);
        // get filename from edittext
        String filename = exportStringFileName;
        // sanity check
        if (filename.equals("")) {
            writeToUiToast("scan a tag before writing the content to a file :-)");
            return;
        }
        intent.putExtra(Intent.EXTRA_TITLE, filename);
        selectTextFileActivityResultLauncher.launch(intent);
    }

    ActivityResultLauncher<Intent> selectTextFileActivityResultLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            new ActivityResultCallback<ActivityResult>() {
                @Override
                public void onActivityResult(ActivityResult result) {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        // There are no request codes
                        Intent resultData = result.getData();
                        // The result data contains a URI for the document or directory that
                        // the user selected.
                        Uri uri = null;
                        if (resultData != null) {
                            uri = resultData.getData();
                            // Perform operations on the document using its URI.
                            try {
                                // get file content from edittext
                                String fileContent = exportString;
                                System.out.println("## data to write: " + exportString);
                                writeTextToUri(uri, fileContent);
                                writeToUiToast("file written to external shared storage: " + uri.toString());
                            } catch (IOException e) {
                                e.printStackTrace();
                                writeToUiToast("ERROR: " + e.toString());
                                return;
                            }
                        }
                    }
                }
            });

    private void writeTextToUri(Uri uri, String data) throws IOException {
        try {
            System.out.println("** data to write: " + data);
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(getApplicationContext().getContentResolver().openOutputStream(uri));
            outputStreamWriter.write(data);
            outputStreamWriter.close();
        } catch (IOException e) {
            System.out.println("Exception File write failed: " + e.toString());
        }
    }

    /**
     * section for options menu
     */

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_activity_main, menu);

        MenuItem mApplications = menu.findItem(R.id.action_applications);
        mApplications.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                allLayoutsInvisible();
                //llApplicationHandling.setVisibility(View.VISIBLE);
                return false;
            }
        });

        MenuItem mStandardFile = menu.findItem(R.id.action_standard_file);
        mStandardFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                allLayoutsInvisible();
                //llStandardFile.setVisibility(View.VISIBLE);
                return false;
            }
        });

        MenuItem mExportTextFile = menu.findItem(R.id.action_export_text_file);
        mExportTextFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Log.i(TAG, "mExportTextFile");
                exportTextFile();
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }

    public void showDialog(Activity activity, String msg) {
        final Dialog dialog = new Dialog(activity);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        dialog.setCancelable(true);
        dialog.setContentView(R.layout.logdata);
        TextView text = dialog.findViewById(R.id.tvLogData);
        //text.setMovementMethod(new ScrollingMovementMethod());
        text.setText(msg);
        Button dialogButton = dialog.findViewById(R.id.btnLogDataOk);
        dialogButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                dialog.dismiss();
            }
        });
        dialog.show();
    }
}