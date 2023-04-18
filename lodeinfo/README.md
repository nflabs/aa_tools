# LODEINFO Triage Tools
Artifact analysis tools for LODEINFO malware.

## How to use

### decode_connection.py
This script decodes and parses the LODEINFO C2 communication.

1. install dependant packages
```
pip install -r requirements.txt
```

2. change the KEY, IV, and SAMPLEDATA environment variables according to your environment and run.
```sh
########
# 
#  KEY = a2b_hex("20AD7B28FE0D2D223C48A76E35EE0DA3AEA2B1175D69804605EC43EA4687F785")
#  IV = a2b_hex("8D5291164B7414118D0C8AC7C050FD1E")
#  SAMPLEDATA = "AB34bTyi5o_=w8VCUPIIRBvPp08lpwxFeug1tuEhYA2BB2MGCvHya2amXKISUQjThbsuNCwLZvSPlSIvGGcNR_MBHzDIu-tDQcViLgCy-Hh4eHh53fGqgnqF5UZQSK-Ree6zdkoavkNz696t-7Wcv684IzZ21rq4OjopCEtVhAqIIL9StMKNZlij_7ZF1Kmp0rMI4rlwX1gPxdGdMvqSgBFilVttK6-aYm3jmsGJ-BdXXimM9GIRelhCPAIEVwWKsYZSCiz3awFKvu7ZvbqDPmS6cQ.."
# 
# #######
❯ python decode_connection.py 
HEADER(sha512_128=b'e87d884fa9005a7c2963b7a41bca4ad2', payload_size=244)
BEACON(data_size=62, random_data_size=24, date=datetime.datetime(2022, 8, 18, 19, 11, 46), ansi='932', mac_addr='000C2932F71A', computer_name='DESKTOP-81OMVP8', xor_key='zlApZbCgpp_', version='v0.6.3', random_data=b'cV4dXd7e5tIKGmK8ZdHBtw..')
```

### triage.py (IDAPython tool)
It decrypts and extracts the malicious shellcode from the file, and detects the AES key and malware version.  
Triage is performed simply by giving this file as input from "Script files..." in IDA Pro.  

#### example
```sh
   [*] Found version info at 0x14874
   [*] Found version info at 0x1adb7
   [*] Maybe, found AES config at 0xc3e9
==============LODEINFO Triage ==============
   - Version: b'v0.6.5'

   - AES KEY: 914bdc493db1da93ed8dcb2edb6a66cc66409651f9bb6544bfae24a79e5fa12e
   - AES  IV: f3c264d1043cd45f8a20c5aa1af62423
   - Vigenere KEY: b'ETnxiVjNKzOiHe'
[*] Executed RawShellcode triage
[*] Triage script: Done
```

#### Supported file types
    - DLL (malicious shellcode is mixed in.)
    - BLOB (encrypted shellcode by 1 byte)
    - Raw shellcode (decrypted shellcode)

### resolve_api_hash.py (IDAPython tool)
This script automatically creates the API structure used in LODEINFO to assist your artifact analysis.
Please change the IDA_PATH environment variable according to your environment.

#### Supported file types
    - Raw shellcode (decrypted shellcode)

## Note
### Tested Environment
|  software |  version  |
| ---- | ---- |
|  IDA Pro  |  8.2  |
|  IDAPython  | v7.4.0  |
|  python | 3.11.1 | 

## Tested malware version
- v0.6.5 (BLOB shellcode)
    - sample encrypted BLOB file: [sample/v065.zip](https://github.com/nflabs/aa_tools/tree/main/lodeinfo/sample/v065.zip)
    - the password is `infected`
- v0.6.3 (BLOB shellcode)
- v0.5.9 (DLL)
- v0.3.5 (DLL)
- v0.1.2 (DLL)
