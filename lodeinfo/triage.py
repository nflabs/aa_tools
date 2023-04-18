import os
import re
import subprocess
from binascii import b2a_hex
from typing import Dict, Iterator, Tuple, List, NamedTuple, Optional, Protocol

import ida_funcs
import ida_nalt
import ida_xref
import idaapi
import idautils
import idc


class AESConfig(NamedTuple):
    address: int
    key: str
    iv: str


class IFTriage(Protocol):
    type: str

    def triage(self, mem: Dict[int, bytes]) -> bool:
        ...

    def __check(self, mem: Dict[int, bytes]) -> bool:
        ...


class DLLTriage:
    type: str = "DLL"

    def triage(self, mem: Dict[int, bytes]) -> bool:
        if not self.__check(mem):
            return False

        shellcode: Optional[bytes] = self.__extract_shellcode(mem)
        if not shellcode:
            return False

        output_filename: str = output_decoded_shellcode(shellcode)
        result: bool = open_encypted_shellcode_with_idapro(output_filename)
        if not result:
            print("[!] This file may be LODEINFO DLL, but decryption was failed")
        return True

    def __check(self, mem: Dict[int, bytes]) -> bool:
        info = idaapi.get_inf_structure()
        return info.is_dll()

    def __extract_shellcode(self, mem: Dict[int, bytes]) -> Optional[bytes]:
        addr: Optional[int] = self.__get_shellcode_address(mem)
        if not addr:
            return None

        frms: List[int] = []
        for xref in idautils.XrefsTo(addr, 0):
            frms.append(xref.frm)

        for frm in frms:
            size: Optional[int] = self.__guess_shellcode_size(frm)
            if size:
                break
        if not size:
            return None

        enc_data: bytes = idc.get_bytes(addr, size)
        return bytes([i ^ enc_data[4] for i in enc_data])

    def __guess_shellcode_size(self, addr: int) -> Optional[int]:
        origin_addr: int = addr
        for _ in range(30):
            addr = idc.prev_head(addr)
            mnem: str = idc.print_insn_mnem(addr)

            if mnem == "mov" and idc.get_operand_type(addr, 1) == idc.o_imm:
                val: int = idc.get_operand_value(addr, 1)
                if val < 0x10000 or val > 0x10000000:
                    continue
                return val
            elif mnem == "push" and idc.get_operand_type(addr, 0) == idc.o_imm:
                val: int = idc.get_operand_value(addr, 0)
                if val < 0x10000 or val > 0x10000000:
                    continue
                return val

        for _ in range(10):
            origin_addr = idc.next_head(origin_addr)
            mnem: str = idc.print_insn_mnem(origin_addr)

            if mnem == "mov" and idc.get_operand_type(origin_addr, 1) == idc.o_imm:
                val: int = idc.get_operand_value(origin_addr, 1)
                if val < 0x10000 or val > 0x10000000:
                    continue
                return val
            elif mnem == "push" and idc.get_operand_type(origin_addr, 0) == idc.o_imm:
                val: int = idc.get_operand_value(origin_addr, 0)
                if val < 0x10000 or val > 0x10000000:
                    continue
                return val

        return None

    def __get_shellcode_address(self, mem: Dict[int, bytes]) -> Optional[int]:
        head: int = self.__get_data_seg_start_addr()
        ref_addresses: List[int] = []
        for i in range(len(mem[head])):
            xref = ida_xref.xrefblk_t()
            if not xref.first_to((head + i), 0):
                continue
            ref_addresses.append(head + i)

        for addr in ref_addresses:
            code: bytes = idc.get_bytes(addr, 5)
            maybe_key: int = code[4]
            if code[0] ^ maybe_key == 0xE9:
                return addr

        return None

    def __get_data_seg_start_addr(self) -> int:
        for segment in idautils.Segments():
            segment_name: str = idc.get_segm_name(segment)
            if segment_name == ".data":
                return idc.get_segm_start(segment)


class EncryptedBLOBTriage:
    type: str = "EncryptedBLOB"

    def triage(self, mem: Dict[int, bytes]) -> bool:
        # file is not a BLOB
        if len(mem) != 1 or not self.__check(mem):
            return False

        output_filename: str = output_decoded_shellcode(list(mem.values())[0])
        result: bool = open_encypted_shellcode_with_idapro(output_filename)
        if not result:
            print(
                "[!] This file may be BLOB LODEINFO shellcode, but decryption was failed"
            )
        return True

    def __check(self, mem: Dict[int, bytes]) -> bool:
        shellcode: bytes = list(mem.values())[0]
        maybe_key: int = shellcode[4]
        if shellcode[0] ^ maybe_key == 0xE9 and shellcode[0] != 0xE9:
            return True
        return False


class RawShellcodeTriage:
    type: str = "RawShellcode"

    def triage(self, mem: Dict[int, bytes]) -> bool:
        idc.auto_wait()
        # file is not a shellcode
        if len(mem) != 1:
            return False

        if not self.__check(mem):
            print("[!] Maybe, this file is not LODEINFO shellcode.")
            return False

        version: Optional[bytes] = extract_version(mem)
        aes_config: Optional[AESConfig] = extract_guessing_AES_config(mem)

        if not version:
            print("[!] Could not found version information. (maybe, not LODEINFO??)")
            return False

        print("==============LODEINFO Triage ==============")
        print(f"   - Version: {version}")

        if not aes_config:
            print("Could not found AES settings, sorry ;(")
            return True

        print("")
        print(f"   - AES KEY: {aes_config.key}")
        print(f"   - AES  IV: {aes_config.iv}")

        if has_vigenere(version):
            v_key: Optional[bytes] = extract_vigenere_key(mem, aes_config.address)
            if v_key:
                print(f"   - Vigenere KEY: {v_key}")
            else:
                print("   ....could not found vigenere key, sorry ;(")

        return True

    def __check(self, mem: Dict[int, bytes]) -> bool:
        shellcode: bytes = list(mem.values())[0]
        if shellcode[0] == 0xE9 and shellcode[4] == 0x00:
            return True
        return False


def get_all_code() -> Dict[int, bytes]:
    mem: Dict[int, bytes] = {}
    for segment in idautils.Segments():
        segment_start: int = idc.get_segm_start(segment)
        segment_end: int = idc.get_segm_end(segment)
        segment_data = idc.get_bytes(
            segment_start,
            segment_end - segment_start,
        )
        # save the bytes like `{0x10001000: b"\xde\xad\xbe\xef......."}`
        mem[segment_start] = segment_data
    return mem


def mem_search(mem: Dict[int, bytes], pattern: bytes) -> List[int]:
    addresses: List[int] = []
    for base_addr, raw_mem in mem.items():
        match: Iterator[re.Match[bytes]] = re.finditer(
            pattern,
            raw_mem,
        )
        if not match:
            continue
        for m in match:
            addresses.append(base_addr + m.start())
    return addresses


def output_decoded_shellcode(encrypted_code: bytes) -> str:
    output_filename: str = f"{ida_nalt.get_input_file_path()}.dec"
    key: int = encrypted_code[4]
    dec: bytes = b""

    for c in encrypted_code:
        dec += bytes([key ^ c])

    with open(output_filename, "wb") as f:
        f.write(dec)

    return output_filename


def open_encypted_shellcode_with_idapro(filename: str) -> bool:
    IDA_PATH = "C:\\Program Files\\IDA Pro 8.2\\ida.exe"
    SCRIPT_PATH = __file__.replace("/", "\\")

    if not os.path.isfile(IDA_PATH):
        print(
            f"""[!] Output decoded shellcode as {filename}, but could not found IDA at {IDA_PATH}
            Please check the "IDA_PATH" variable!
            """
        )
        return False
    try:
        subprocess.run(
            [
                IDA_PATH,
                "-A",
                f"-S{SCRIPT_PATH}",
                filename,
            ],
        )
    except Exception as e:
        print(f"[!] Error has occured in subprocess, as: {e}")
        return False
    return True


def extract_guessing_AES_config(mem: Dict[int, bytes]) -> Optional[AESConfig]:
    aes_config_pattern: List[bytes] = [
        rb"(?<!\xc7\x45(.|\s){5})(\xc7\x45(.|\s){5}){12}[^\xc7]",
        rb"(?<!\xc7\x44(.|\s){6})(\xc7\x44(.|\s){6}){12}[^\xc7]",
    ]
    addresses: List[int] = []
    for pattern in aes_config_pattern:
        addresses.extend(mem_search(mem, pattern))
    if not addresses:
        return None

    if len(addresses) != 1:
        addr: int = __guess_most_sus_address(addresses)
    else:
        addr: int = addresses[0]

    if not addr:
        return None

    print(f"   [*] Maybe, found AES config at {hex(addr)}")

    key: List[bytes] = []
    iv: List[bytes] = []
    head_addr: int = addr

    for _ in range(8):
        key.append(idc.get_operand_value(addr, 1).to_bytes(4, "little"))
        addr = idc.next_head(addr)
    for _ in range(4):
        iv.append(idc.get_operand_value(addr, 1).to_bytes(4, "little"))
        addr = idc.next_head(addr)

    return AESConfig(
        address=head_addr,
        key="".join([b2a_hex(n).decode() for n in key]),
        iv="".join([b2a_hex(n).decode() for n in iv]),
    )


def __guess_most_sus_address(addresses: List[int]) -> int:
    AES_CONFIG_LEN = int(48 / 4)

    try:
        for addr in addresses:
            head_addr = addr
            for _ in range(AES_CONFIG_LEN):
                maybe_key = idc.get_operand_value(addr, 1).to_bytes(4, "little")
                maybe_key.decode()
                addr = next_head(addr)
    except UnicodeDecodeError:
        return head_addr

    return 0


def extract_version(mem: Dict[int, bytes]) -> Optional[bytes]:
    version_pattern: bytes = rb"\xc7\x45.\x76\x30\x2e.{5,10}\x2e"

    addressess: List[int] = mem_search(mem, version_pattern)
    if not addressess:
        return None

    for addr in addressess:
        print(f"   [*] Found version info at {hex(addr)}")
    func = ida_funcs.get_func(addr)

    version = b""
    counter = 0
    for ea in idautils.Heads(addr, func.end_ea):
        mnem: str = idc.print_insn_mnem(ea)
        ope_type: int = idc.get_operand_type(ea, 1)

        if mnem == "mov" and ope_type == idc.o_imm:
            v_str = idc.get_operand_value(ea, 1)
            version += v_str.to_bytes(int(len(hex(v_str).lstrip("0x")) / 2), "little")
            counter += 1

        if counter > 1:
            break

    return version


def extract_vigenere_key(mem: Dict[int, bytes], addr: int) -> Optional[bytes]:
    vigenere_key_pattern: bytes = rb"\xc7\x45.\w{4}"
    
    addressess: List[int] = mem_search(mem, vigenere_key_pattern)
    func = ida_funcs.get_func(addr)
    v_addressess: List[int]= [i for i in addressess if i < addr and i > func.start_ea]
    if not v_addressess:
        return None
    
    head: int = min(v_addressess)
    if re.search("dword ptr \[(.*)\]", idc.print_operand(head, 0)):
        sorted_v_key: List[Tuple[int, int]] = __extract_vigenere_key_from_decompiler_mode(head, addr)
    elif re.search("\[ebp\+var_(.*)\]", idc.print_operand(head, 0)):
        sorted_v_key: List[Tuple[int, int]] = __extract_vigenere_key_from_assembly_mode(head, addr)
    else:
        return None
        
    vigenere_key = b""
    for _, v_key_str in sorted_v_key:
        vigenere_key += v_key_str.to_bytes(int(len(hex(v_key_str).lstrip("0x")) / 2), "little")

    return vigenere_key


def __extract_vigenere_key_from_decompiler_mode(head: int, addr: int) -> List[Tuple[int, int]]:
    stack_addr: str = re.search("dword ptr \[(.*)\]", idc.print_operand(head, 0)).group(1)
    vigenere_key_dict: Dict[int, int] = {}
    for ea in idautils.Heads(head, addr):
        mnem: str = idc.print_insn_mnem(ea)
        ope: str = idc.print_operand(ea, 0)
        if not (mnem == "mov" and stack_addr in ope):
            continue
        escape_str: str = stack_addr.replace("+", "\+")
        if re.search(f"dword ptr \[{escape_str}\+(.*)\]", ope) is None and "dword ptr" in ope:
            vigenere_key_dict[0] = idc.get_operand_value(ea, 1)
            continue
        offset_str: str = re.search(f"\[{escape_str}\+(.*)\]", ope).group(1)
        offset: int = int(offset_str.replace("h", ""), 16)
        vigenere_key_dict[offset] = idc.get_operand_value(ea, 1)
    
    return sorted(vigenere_key_dict.items())


def __extract_vigenere_key_from_assembly_mode(head: int, addr: int) -> List[Tuple[int, int]]:
    stack_addr: int = int("0x" + re.search("\[ebp\+var_(.*)\]", idc.print_operand(head, 0)).group(1), 16)
    vigenere_key_dict: Dict[int, int] = {}
    for ea in idautils.Heads(head, addr):
        mnem: str = idc.print_insn_mnem(ea)
        ope: str = idc.print_operand(ea, 0)
        if not (mnem == "mov" and "[ebp+var_" in ope):
            continue
        offset_search = re.search("\[ebp\+var_(.*)\]", ope)
        if not offset_search:
            continue
        offset: int = int("0x" + offset_search.group(1), 16)
        if offset > stack_addr:
            continue
        vigenere_key_dict[stack_addr-offset] = idc.get_operand_value(ea, 1)

    return sorted(vigenere_key_dict.items())


def has_vigenere(version: bytes) -> bool:
    v: int = int(version.replace(b"v", b"").replace(b".", b""))
    # over v0.5.6, data was encrypted with Vigenere cipher.
    if v >= 56:
        return True
    return False
    

def main() -> None:
    mem: Dict[int, bytes] = get_all_code()

    triage_helpers: List[IFTriage] = [
        DLLTriage(),
        EncryptedBLOBTriage(),
        RawShellcodeTriage(),
    ]

    for helper in triage_helpers:
        success: bool = helper.triage(mem=mem)
        if success:
            print(f"[*] Executed {helper.type} triage")
            break

    print("[*] Triage script: Done")


if __name__ == "__main__":
    main()
