import re
import base64
from binascii import a2b_hex, b2a_hex
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import quicklz
from Crypto.Cipher import AES

KEY = a2b_hex("20AD7B28FE0D2D223C48A76E35EE0DA3AEA2B1175D69804605EC43EA4687F785")
IV = a2b_hex("8D5291164B7414118D0C8AC7C050FD1E")
VIGENERE_KEY = "zlApZbCgpp_"

SAMPLEDATA = "AB34bTyi5o_=w8VCUPIIRBvPp08lpwxFeug1tuEhYA2BB2MGCvHya2amXKISUQjThbsuNCwLZvSPlSIvGGcNR_MBHzDIu-tDQcViLgCy-Hh4eHh53fGqgnqF5UZQSK-Ree6zdkoavkNz696t-7Wcv684IzZ21rq4OjopCEtVhAqIIL9StMKNZlij_7ZF1Kmp0rMI4rlwX1gPxdGdMvqSgBFilVttK6-aYm3jmsGJ-BdXXimM9GIRelhCPAIEVwWKsYZSCiz3awFKvu7ZvbqDPmS6cQ.."


@dataclass
class HEADER:
    sha512_128: bytes
    payload_size: int


@dataclass
class BEACON:
    data_size: int
    random_data_size: int
    date: datetime
    ansi: str
    mac_addr: str
    computer_name: str
    xor_key: Optional[str]
    version: Optional[str]
    random_data: Optional[bytes]


class LODEINFOConnection:
    TABLE = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    def __init__(self, data):
        self.data_size = len(data)
        query_index = data.find("=")
        post_key = data[:query_index]
        main_data = data[query_index + 1 :]
        self.header = self.__dec_header(post_key, main_data[:0x1C])
        self.post_datasize = int.from_bytes(self.header[0x10:0x14], byteorder="little")
        self.post_data = self.__dec_custom_base64(
            main_data[0x1C : 0x1C + self.post_datasize]
        )

    def __dec_header(self, post_key: str, data: str) -> str:
        # convert real base64 data
        b64_data = ""
        for i, d in enumerate(data):
            if self.TABLE.find(ord(d)) == -1:
                b64_data += d
                continue
            k: str = post_key[i % len(post_key)]
            b64_data += chr(
                self.TABLE[(self.TABLE.find(ord(d)) - self.TABLE.find(ord(k))) % 62]
            )
        decode_b64: bytes = self.__dec_custom_base64(b64_data)
        if int.from_bytes(decode_b64[0x10:0x14], byteorder="little") > self.data_size:
            return self.__dec_custom_base64(data)

        return decode_b64

    def __dec_custom_base64(self, data):
        data = data.replace(".", "=").replace("_", "/").replace("-", "+")
        return base64.b64decode(data)

    def decrypt(self, key, iv):
        try:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            dec_size = int.from_bytes(
                [b ^ self.post_data[0x34] for b in self.post_data[0x30:0x34]],
                byteorder="little",
            )
            dec_data = cipher.decrypt(self.post_data[0x35 : 0x35 + dec_size])
        except ValueError:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            dec_size = int.from_bytes(self.post_data[0x30:0x34], byteorder="little")
            dec_data = cipher.decrypt(self.post_data[0x34 : 0x34 + dec_size])

        j_size = dec_data[-1]
        try:
            dec = quicklz.decompress(dec_data[4 : dec_size - j_size])
        except ValueError:
            dec = quicklz.decompress(dec_data[: dec_size - j_size])
        return dec

    def parse_header(self) -> HEADER:
        return HEADER(
            sha512_128=b2a_hex(self.header[:0x10]),
            payload_size=int.from_bytes(self.header[0x10:0x14], byteorder="little"),
        )

    def parse_decrypted_data(self, data: bytes) -> BEACON:
        data_size: int = int.from_bytes(data[0:0x4], byteorder="little")
        random_data_size: int = int.from_bytes(data[0x4:0x8], byteorder="little")
        datetime_end_offset: int = data.find(b"|", 0x11)
        ansi_end_offset: int = data.find(b"|", datetime_end_offset + 1)
        mac_addr_offset: int = data.find(b"|", ansi_end_offset + 1)

        return BEACON(
            data_size=data_size,
            random_data_size=random_data_size,
            date=datetime.fromtimestamp(int(data[0x11:datetime_end_offset])),
            ansi=data[datetime_end_offset + 1 : ansi_end_offset].decode(),
            mac_addr=data[ansi_end_offset + 1 : mac_addr_offset].decode(),
            computer_name=self.__get_computername(data, b"#", mac_addr_offset + 1),
            xor_key=self.__get_xor_key(data, b"-", self.computername_end_offset + 1),
            version=self.__get_version(data, self.computername_end_offset + 1),
            random_data=data[data_size + 27 : data_size + 27 + random_data_size]
            if random_data_size
            else None,
        )

    def __get_computername(self, data: bytes, word: bytes, start: int) -> Optional[str]:
        computername_end_offset: int = data.find(word, start)
        if b"\x00" in data[start:computername_end_offset]:
            computername_end_offset = data.find(b"\x00", start)

        self.computername_end_offset = computername_end_offset
        return data[start:computername_end_offset].decode()

    def __get_xor_key(self, data: bytes, word: bytes, start: int) -> Optional[str]:
        xor_key_offset: int = data.find(word, start)
        if xor_key_offset < 0:
            return None

        if b"\x00" in data[start:xor_key_offset]:
            xor_key_offset = data.find(b"\x00", start)

        self.xor_key = xor_key_offset
        return data[start:xor_key_offset].decode()

    def __get_version(self, data: bytes, start: int) -> Optional[str]:
        pattern = b".*?(v\\d.\\d.\\d)"
        result = re.match(pattern, data[start:])
        if not result:
            return None

        return result.group(1).decode()


if __name__ == "__main__":
    if not "=" in SAMPLEDATA:
        SAMPLEDATA = VIGENERE_KEY + "=" + SAMPLEDATA
    li = LODEINFOConnection(SAMPLEDATA)
    data = li.decrypt(KEY, IV)
    print(li.parse_header())
    if "=" in SAMPLEDATA:
        print(li.parse_decrypted_data(data))
    else:
        print(data)
