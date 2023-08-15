# changeAuthenticationModeFromAesToLrp

```plaintext
method: changeAuthenticationModeFromAesToLrp: started
method: changeAuthenticationModeFromAesToLrp: CmdCounter: 0
method: changeAuthenticationModeFromAesToLrp: commandCounterLsb1 length: 2 data: 0000
method: changeAuthenticationModeFromAesToLrp: ivInput length: 16 data: a55afd9e870100000000000000000000
method: changeAuthenticationModeFromAesToLrp: SesAuthENCKey length: 16 data: 6043911b14d98eabfd7280f51abb4b45
encrypt with myIV length: 16 data: 00000000000000000000000000000000 myKey length: 16 data: 6043911b14d98eabfd7280f51abb4b45 myMsg length: 16 data: a55afd9e870100000000000000000000
method: changeAuthenticationModeFromAesToLrp: ivForCmdData length: 16 data: 6f5f7b77a89ed6516249f3f744c67107
method: changeAuthenticationModeFromAesToLrp: commandDataPadded length: 16 data: 00000000020000000000800000000000
encrypt with myIV length: 16 data: 6f5f7b77a89ed6516249f3f744c67107 myKey length: 16 data: 6043911b14d98eabfd7280f51abb4b45 myMsg length: 16 data: 00000000020000000000800000000000
method: changeAuthenticationModeFromAesToLrp: encryptedData length: 16 data: f79bb2b381791159d1aa652d958fc12a
method: changeAuthenticationModeFromAesToLrp: macInput length: 24 data: 5c0000fd9e870105f79bb2b381791159d1aa652d958fc12a
method: changeAuthenticationModeFromAesToLrp: SesAuthMACKey length: 16 data: 1f52de5e1281e97b88bf2a9b00ecb50f
calculateDiverseKey masterKey length: 16 data: 1f52de5e1281e97b88bf2a9b00ecb50f input length: 24 data: 5c0000fd9e870105f79bb2b381791159d1aa652d958fc12a
method: changeAuthenticationModeFromAesToLrp: macFull length: 16 data: 713cc2d8114174a7ecf0ab089956712b
method: truncateMAC: fullMAC length: 16 data: 713cc2d8114174a7ecf0ab089956712b
method: truncateMAC: truncatedMAC length: 8 data: 3cd841a7f008562b
method: changeAuthenticationModeFromAesToLrp: macTruncated length: 8 data: 3cd841a7f008562b
method: changeAuthenticationModeFromAesToLrp: SetConfigurationCommand length: 25 data: 05f79bb2b381791159d1aa652d958fc12a3cd841a7f008562b
method: sendData: send apdu --> length: 31 data: 905c00001905f79bb2b381791159d1aa652d958fc12a3cd841a7f008562b00
method: sendData: received  <-- length: 2 data: 9100
changeAuthenticationModeFromAesToLrp SUCCESS
method: changeAuthenticationModeFromAesToLrp: the CmdCounter is increased by 1 to 1
errorCode length: 2 data: 9100
errorCodeReason: TEST FAILURE
logData:

authenticateAesEv2First:
keyNo: 0 key length: 16 data: 00000000000000000000000000000000


authenticateAesEv2First:
step 01 get encrypted rndB from card


authenticateAesEv2First:
This method is using the AUTHENTICATE_AES_EV2_FIRST_COMMAND so it will work with AES-based application only


authenticateAesEv2First:
parameter length: 2 data: 0000


authenticateAesEv2First:
get enc rndB apdu length: 8 data: 9071000002000000


sendData:
send apdu --> length: 8 data: 9071000002000000


sendData:
received  <-- length: 18 data: 67cee03aab35edf30ee74b49f21bb23f91af


authenticateAesEv2First:
get enc rndB response length: 18 data: 67cee03aab35edf30ee74b49f21bb23f91af


authenticateAesEv2First:
encryptedRndB length: 16 data: 67cee03aab35edf30ee74b49f21bb23f


authenticateAesEv2First:
step 02 iv0 is 16 zero bytes iv0 length: 16 data: 00000000000000000000000000000000


authenticateAesEv2First:
step 03 decrypt the encryptedRndB using AES.decrypt with key key length: 16 data: 00000000000000000000000000000000 iv0 length: 16 data: 00000000000000000000000000000000


authenticateAesEv2First:
rndB length: 16 data: ff2d73c0573a79592e32fab176108f0d


authenticateAesEv2First:
step 04 rotate rndB to LEFT


rotateLeft:
data length: 16 data: ff2d73c0573a79592e32fab176108f0d


authenticateAesEv2First:
rndB_leftRotated length: 16 data: 2d73c0573a79592e32fab176108f0dff


authenticateAesEv2First:
step 05 generate a random rndA


getRandomData:
key length: 16 data: 00000000000000000000000000000000


getRandomData:
length: 16


authenticateAesEv2First:
rndA length: 16 data: 25f512031e91465d3f7f9e8c12db7cfa


authenticateAesEv2First:
step 06 concatenate rndA | rndB_leftRotated


authenticateAesEv2First:
rndArndB_leftRotated length: 32 data: 25f512031e91465d3f7f9e8c12db7cfa2d73c0573a79592e32fab176108f0dff


authenticateAesEv2First:
step 07 iv1 is 16 zero bytes


authenticateAesEv2First:
iv1 length: 16 data: 00000000000000000000000000000000


authenticateAesEv2First:
step 08 encrypt rndArndB_leftRotated using AES.encrypt and iv1


authenticateAesEv2First:
rndArndB_leftRotated_enc length: 32 data: 159862989c5563f7d39ec459c0188539e62e8725ec374a169c595b82275dfd48


authenticateAesEv2First:
step 09 send the encrypted data to the PICC


authenticateAesEv2First:
send rndArndB_leftRotated_enc apdu length: 38 data: 90af000020159862989c5563f7d39ec459c0188539e62e8725ec374a169c595b82275dfd4800


sendData:
send apdu --> length: 38 data: 90af000020159862989c5563f7d39ec459c0188539e62e8725ec374a169c595b82275dfd4800


sendData:
received  <-- length: 34 data: 517502d5de08c8240a67f318b2140b0daea79063297b0e6be491cb05d5ea2c209100


authenticateAesEv2First:
send rndArndB_leftRotated_enc response length: 34 data: 517502d5de08c8240a67f318b2140b0daea79063297b0e6be491cb05d5ea2c209100


authenticateAesEv2First:
step 10 received encrypted data from PICC


authenticateAesEv2First:
data_enc length: 32 data: 517502d5de08c8240a67f318b2140b0daea79063297b0e6be491cb05d5ea2c20


authenticateAesEv2First:
step 11 iv2 is 16 zero bytes


authenticateAesEv2First:
iv2 length: 16 data: 00000000000000000000000000000000


authenticateAesEv2First:
step 12 decrypt data_enc with iv2 and key


authenticateAesEv2First:
data length: 32 data: fd9e8701f512031e91465d3f7f9e8c12db7cfa25000000000000000000000000


authenticateAesEv2First:
step 13 full data needs to get split up in 4 values


authenticateAesEv2First:
data length: 32 data: fd9e8701f512031e91465d3f7f9e8c12db7cfa25000000000000000000000000


authenticateAesEv2First:
ti length: 4 data: fd9e8701


authenticateAesEv2First:
rndA_leftRotated length: 16 data: f512031e91465d3f7f9e8c12db7cfa25


authenticateAesEv2First:
pDcap2 length: 6 data: 000000000000


authenticateAesEv2First:
pCDcap2 length: 6 data: 000000000000


authenticateAesEv2First:
step 14 rotate rndA_leftRotated to RIGHT


rotateRight:
data length: 16 data: f512031e91465d3f7f9e8c12db7cfa25


authenticateAesEv2First:
rndA_received  length: 16 data: 25f512031e91465d3f7f9e8c12db7cfa


authenticateAesEv2First:
rndA           length: 16 data: 25f512031e91465d3f7f9e8c12db7cfa


authenticateAesEv2First:
rndA and rndA received are equal: true


authenticateAesEv2First:
rndB           length: 16 data: ff2d73c0573a79592e32fab176108f0d


authenticateAesEv2First:
**** auth result ****


authenticateAesEv2First:
*** AUTHENTICATED ***


getSesAuthEncKey:
rndA length: 16 data: 25f512031e91465d3f7f9e8c12db7cfa rndB length: 16 data: ff2d73c0573a79592e32fab176108f0d authenticationKey length: 16 data: 00000000000000000000000000000000


getSesAuthEncKey:
rndA      length: 16 data: 25f512031e91465d3f7f9e8c12db7cfa


getSesAuthEncKey:
rndA02to07 length: 6 data: 12031e91465d


getSesAuthEncKey:
rndB      length: 16 data: ff2d73c0573a79592e32fab176108f0d


getSesAuthEncKey:
rndB00to05 length: 6 data: ff2d73c0573a


xor:
dataA length: 6 data: 12031e91465d dataB length: 6 data: ff2d73c0573a


getSesAuthEncKey:
xored      length: 6 data: ed2e6d511167


getSesAuthEncKey:
rndA      length: 16 data: 25f512031e91465d3f7f9e8c12db7cfa


getSesAuthEncKey:
rndB      length: 16 data: ff2d73c0573a79592e32fab176108f0d


getSesAuthEncKey:
cmacInput length: 32 data: a55a0001008025f5ed2e6d51116779592e32fab176108f0d3f7f9e8c12db7cfa


getSesAuthEncKey:
iv        length: 16 data: 00000000000000000000000000000000


getSesAuthEncKey:
cmacOut  length: 16 data: 6043911b14d98eabfd7280f51abb4b45


getSesAuthMacKey:
rndA length: 16 data: 25f512031e91465d3f7f9e8c12db7cfa rndB length: 16 data: ff2d73c0573a79592e32fab176108f0d authenticationKey length: 16 data: 00000000000000000000000000000000


getSesAuthMacKey:
rndA      length: 16 data: 25f512031e91465d3f7f9e8c12db7cfa


getSesAuthMacKey:
rndA02to07 length: 6 data: 12031e91465d


getSesAuthMacKey:
rndB      length: 16 data: ff2d73c0573a79592e32fab176108f0d


getSesAuthMacKey:
rndB00to05 length: 6 data: ff2d73c0573a


xor:
dataA length: 6 data: 12031e91465d dataB length: 6 data: ff2d73c0573a


getSesAuthMacKey:
xored      length: 6 data: ed2e6d511167


getSesAuthMacKey:
rndA      length: 16 data: 25f512031e91465d3f7f9e8c12db7cfa


getSesAuthMacKey:
rndB      length: 16 data: ff2d73c0573a79592e32fab176108f0d


getSesAuthMacKey:
cmacInput length: 32 data: 5aa50001008025f5ed2e6d51116779592e32fab176108f0d3f7f9e8c12db7cfa


getSesAuthMacKey:
iv        length: 16 data: 00000000000000000000000000000000


getSesAuthMacKey:
cmacOut  length: 16 data: 1f52de5e1281e97b88bf2a9b00ecb50f


authenticateAesEv2First:
SesAuthENCKey  length: 16 data: 6043911b14d98eabfd7280f51abb4b45


authenticateAesEv2First:
SesAuthMACKey  length: 16 data: 1f52de5e1281e97b88bf2a9b00ecb50f


authenticateAesEv2First:
*********************


changeAuthenticationModeFromAesToLrp:
started


changeAuthenticationModeFromAesToLrp:
CmdCounter: 0


changeAuthenticationModeFromAesToLrp:
commandCounterLsb1 length: 2 data: 0000


changeAuthenticationModeFromAesToLrp:
ivInput length: 16 data: a55afd9e870100000000000000000000


changeAuthenticationModeFromAesToLrp:
SesAuthENCKey length: 16 data: 6043911b14d98eabfd7280f51abb4b45


changeAuthenticationModeFromAesToLrp:
ivForCmdData length: 16 data: 6f5f7b77a89ed6516249f3f744c67107


changeAuthenticationModeFromAesToLrp:
commandDataPadded length: 16 data: 00000000020000000000800000000000


changeAuthenticationModeFromAesToLrp:
encryptedData length: 16 data: f79bb2b381791159d1aa652d958fc12a


changeAuthenticationModeFromAesToLrp:
macInput length: 24 data: 5c0000fd9e870105f79bb2b381791159d1aa652d958fc12a


changeAuthenticationModeFromAesToLrp:
SesAuthMACKey length: 16 data: 1f52de5e1281e97b88bf2a9b00ecb50f


changeAuthenticationModeFromAesToLrp:
macFull length: 16 data: 713cc2d8114174a7ecf0ab089956712b


truncateMAC:
fullMAC length: 16 data: 713cc2d8114174a7ecf0ab089956712b


truncateMAC:
truncatedMAC length: 8 data: 3cd841a7f008562b


changeAuthenticationModeFromAesToLrp:
macTruncated length: 8 data: 3cd841a7f008562b


changeAuthenticationModeFromAesToLrp:
SetConfigurationCommand length: 25 data: 05f79bb2b381791159d1aa652d958fc12a3cd841a7f008562b


sendData:
send apdu --> length: 31 data: 905c00001905f79bb2b381791159d1aa652d958fc12a3cd841a7f008562b00


sendData:
received  <-- length: 2 data: 9100


changeAuthenticationModeFromAesToLrp:
the CmdCounter is increased by 1 to 1

testEnableLrpMode SUCCESS
```