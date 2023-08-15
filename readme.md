# Talk to your Mifare NTAG424 DNA card

This is a sample app to demonstrate how to work with a Mifare NTAG424DNA card. 

If you are going to buy these tags just have a look at the offer by **shopNfc**

https://www.shopnfc.com/en/nfc-stickers/487-nfc-stickers-ntag424-dna-d22mm.html

They cost about 1 Euro per piece (minimum quantity of 10 pieces) and it's a free 
delivery around the world.

Note: I am not affiliated to shopNfc and I don't get any reward for these lines.

## project / app status

At the moment the  app is just a stub with no real functions as it is a 1:1 copy 
of the "Talk to your Mifare DESFire EV1/EV2/EV3" project.

The app description is copied as well so please do not rely on any wording or code 
in this repo so far !


Original description follows:

For simplicity this app uses a DESFire tag with **factory settings** means:

- it uses **Plain communication** only (no MACed or Enciphered Communication)
- it shows how to work with **Standard Files** only (no Backup, Value, Linear Record, Cyclic Record or TransactionMAC Files)
- there are 2 **Access modes** hardcoded: **Free Access** (use without any key) and **Key Secured Access** with 5 predefined keys
  (0 = Application Master Key, 1 = Read & Write access key, 2 = Change Access Rights key, 3 = Read access key and 4 = Write access key)
- it works with a predefined **Application Identifier** (AID) of "D1D2D3"
- the  Standard files have a hardcoded size of 32 bytes
- the app is working with **DES keys** only and the **Master Application KEY** and it's **Key Settings** remain unchanged to prevent from any damage to the card

As the **Authentication** with a key is essentially for a successful transaction there is a huge amount of code lines taken from another 
project. I copied all necessary code from the **NFCJLIB project** available here: https://github.com/andrade/nfcjlib which is provided 
by **Daniel Andrade**, thanks a lot for his contribution. Please obey the LICENCE here: https://github.com/andrade/nfcjlib/blob/master/LICENSE.

The only 'official' information's on DESFire EVx cards can be found here (yes, you understand it right - 'official' and useful 
documentation is available only on another card type, the DESFire Light tag): 

Data sheet – MIFARE DESFire Light: https://www.nxp.com/docs/en/data-sheet/MF2DL_H_x0.pdf

Application note – AN12343 MIFARE DESFire Light Features and Hints: https://www.nxp.com/docs/en/application-note/AN12343.pdf

Leakage Resilient Primitive (LRP) Specification: https://www.nxp.com/docs/en/application-note/AN12304.pdf (test vectors)

Symmetric key diversification's: https://www.nxp.com/docs/en/application-note/AN10922.pdf

System level security measures for MIFARE installations: https://www.nxp.com/docs/en/application-note/AN10969.pdf

For differences between Mifare DESFire EVx versions see: MIFARE DESFire EV3 contactless multi-application IC MF3DHx3_SDS.pdf (page 5)

DESFire protocol (overview about DESFire EV1 commands): https://github.com/revk/DESFireAES/blob/master/DESFire.pdf

NTAG 424 DNA NT4H2421Gx.pdf: https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf

NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf: https://www.nxp.com/docs/en/application-note/AN12196.pdf

NFCJLIB library: https://github.com/andrade/nfcjlib

Type of messaging:
- plain communication
- MACed communication
- fully enciphered communication using DES, TDES or AES keys
- AES Secure Messaging
- LRP Secure Messaging (Leakage Resilient Primitive)

This app always uses ISO/IEC 7816-4 wrapped comands.  

Mifare type identification procedure AN10833.pdf

Note: a 0x9D error ('Permission denied') may occur when sesTMC reached its maximal value or TMCLimit was reached. 

```plaintext
However, I can provide you with the following information about the "SET CONFIGURATION" command:

The command is used to configure the settings of a Mifare DESFire EV3 card.
The command has the following format:
SET CONFIGURATION <option> <value>
The <option> field specifies the setting to be configured.
The <value> field specifies the value for the setting.
The following table lists the possible options for the <option> field:

Option	Description
01	Enable or disable the transaction timer.
02	Set the value of the transaction timer.
03	Enable or disable the access control feature.
04	Set the value of the access control key.


The value for enabling the transaction timer is 0x01. The value for disabling the transaction timer is 0x00.

enable: private static final byte[] SET_CONFIGURATION_COMMAND = {0x00, 0x03, 0x01, 0x01};
disable: private static final byte[] SET_CONFIGURATION_COMMAND = {0x00, 0x03, 0x01, 0x00};

```

Mifare® Application Programming Guide for DESFire (2011): https://www.cardlogix.com/wp-content/uploads/MIFARE-Application-Programming-Guide-for-DESFfire_rev.e.pdf


in DesfireAuthenticateEv2:
public boolean changeFileSettingsSdmEv2(byte fileNumber) {
NOT working although test is success
eventually the file needs to get the sdm options on setup even if disabled
todo check with real tag if fileSettings are "prepared" for SDM usage
see page 4 of video/slideshow https://www.slideshare.net/NXPMIFARETeam/secure-dynamic-messaging-feature
"The SDM feature is enablement is done during the creation of the NDEF file, a Standard Data File inside the Mifare DESFire application"

## Enabling Secure Dynamic Messaging (SDM) on a NTAG 424 DNA and mirroring UID and ReadCounter

TagInfo output for a NTAG 424 DNA with enabled SDM using example values from NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf

```plaintext
-- NDEF ------------------------------

# NFC data set information:
NDEF message containing 1 record
Current message size: 81 bytes
Maximum message size: 254 bytes
NFC data set access: Read & Write

# Record #1: URI record:
Type Name Format: NFC Forum well-known type
Short Record
type: "U"
protocol field: https://
URI field: choose.url.com/ntag424?e=51BAE81E642E493945321C815A200075&c=2446E527C37E073A
Payload length: 77 bytes
Payload data:

[00] 04 63 68 6F 6F 73 65 2E 75 72 6C 2E 63 6F 6D 2F |.choose.url.com/|
[10] 6E 74 61 67 34 32 34 3F 65 3D 35 31 42 41 45 38 |ntag424?e=51BAE8|
[20] 31 45 36 34 32 45 34 39 33 39 34 35 33 32 31 43 |1E642E493945321C|
[30] 38 31 35 41 32 30 30 30 37 35 26 63 3D 32 34 34 |815A200075&c=244|
[40] 36 45 35 32 37 43 33 37 45 30 37 33 41          |6E527C37E073A   |

# NDEF message:
[00] D1 01 4D 55 04 63 68 6F 6F 73 65 2E 75 72 6C 2E |..MU.choose.url.|
[10] 63 6F 6D 2F 6E 74 61 67 34 32 34 3F 65 3D 35 31 |com/ntag424?e=51|
[20] 42 41 45 38 31 45 36 34 32 45 34 39 33 39 34 35 |BAE81E642E493945|
[30] 33 32 31 43 38 31 35 41 32 30 30 30 37 35 26 63 |321C815A200075&c|
[40] 3D 32 34 34 36 45 35 32 37 43 33 37 45 30 37 33 |=2446E527C37E073|
[50] 41                                              |A               |

# Configuration Information:
Secure Dynamic Messaging: Enabled
UID Mirroring: Enabled
SDM Read Counter: Enabled
SDM Read Counter Limit: Disabled
Encrypted File Data Mirroring: Disabled

Application configuration (DF 0xD2760000850101):
* Default AppMasterKey
* Key configuration:
  - 5 mutable AES 128 bit AppKeys
  
Settings for file 02:
* FileType: StandardData file
* Secure Dynamic Messaging: enabled
* Communication mode: plain

* Permissions:
	- ReadWrite: with key 0x0
	- Change: with key 0x0
	- Read: free access
	- Write: with key 0x0

* File size: 256 bytes

* SDM mirror options: 
	- UID mirror enabled
	- SDMReadCtr enabled
	- ASCII encoding

* SDM Access rights:
	- SDMCtrRet permissions: with key 0x1
	- Meta Read: PICCData mirror encrypted with key 0x2
	- File Read: with key 0x1
* PICCData mirror offset: 0x200000
* SDM MAC input offset: 0x430000
* SDM MAC mirror offset: 0x430000  

[000]   00 51 D1 01 4D 55 04 63 68 6F 6F 73 65 2E 75 72 |.Q..MU.choose.ur|
[010]   6C 2E 63 6F 6D 2F 6E 74 61 67 34 32 34 3F 65 3D |l.com/ntag424?e=|
[020]   30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 |0000000000000000|
[030]   30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 |0000000000000000|
[040]   26 63 3D 30 30 30 30 30 30 30 30 30 30 30 30 30 |&c=0000000000000|
[050]   30 30 30 00 00 00 00 00 00 00 00 00 00 00 00 00 |000.............|

```

```plaintext

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
     * Messaging (AES)   |          ||           | 9dh                | available possible
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

```

