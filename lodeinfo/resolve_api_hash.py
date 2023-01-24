import os
import re
import sqlite3
import sys
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Protocol

import ida_funcs
import ida_nalt
import ida_struct
import idaapi
import idautils
import idc


@dataclass
class HashFunc:
    address: int
    xor_key: int


class IFAPIHashSearch(Protocol):
    pattern: bytes

    def search(self, mem: Dict[int, bytes]) -> Optional[HashFunc]:
        ...


class CRC32Search:
    pattern: bytes = rb"\x78\x3b\xf6\x82"

    def search(self, mem: Dict[int, bytes]) -> Optional[HashFunc]:
        addressess: List[int] = mem_search(mem, self.pattern)
        if not addressess:
            return None
        return HashFunc(address=addressess[0], xor_key=0)


class JSHashSearch:
    pattern: bytes = rb"\xa7\xc6\x67\x4e"

    def search(self, mem: Dict[int, bytes]) -> Optional[HashFunc]:
        addressess: List[int] = mem_search(mem, self.pattern)
        if not addressess:
            return None
        func = ida_funcs.get_func(addressess[0])
        for ea in idautils.Heads(func.start_ea, func.end_ea):
            mnem: str = idc.print_insn_mnem(ea)
            ope_type: int = idc.get_operand_type(ea, 1)

            if mnem == "xor" and ope_type == idc.o_imm:
                return HashFunc(
                    address=func.start_ea, xor_key=idc.get_operand_value(ea, 1)
                )


class LODEINFO_APIHASH_ANALYZER:
    def __init__(self):
        self.mem: Dict[int, bytes] = self.__get_all_shellcode()

    def __get_all_shellcode(self) -> Dict[int, bytes]:
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

    def get_xref_addresses(self, addr: int) -> List[int]:
        # get the all of xrefs address for `addr`.
        return [ref.frm for ref in idautils.XrefsTo(addr)]

    def search_func_for_resolve_api(self, addr: int) -> int:
        refs: List[int] = self.get_xref_addresses(addr)
        if len(refs) > 100:
            return addr
        for ref in refs:
            func_start_addr: int = ida_funcs.get_func(ref).start_ea
            return self.search_func_for_resolve_api(func_start_addr)

    def get_api_hash_value(self, addr: int) -> Optional[int]:
        for _ in range(10):
            addr: int = idc.prev_head(addr)
            mnem: str = idc.print_insn_mnem(addr)
            ope_1st: str = idc.print_operand(addr, 0)
            ope_type: int = idc.get_operand_type(addr, 1)

            if mnem == "mov" and ope_1st == "edx" and ope_type == idc.o_imm:
                return idc.get_operand_value(addr, 1)

        return None


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
            # if pattern was found, calc the RVA
            # and the address of the function where the pattern exists
            func_start_addr: int = ida_funcs.get_func(base_addr + m.start()).start_ea
            addresses.append(func_start_addr)
    return addresses


def get_apiname_from_hash(hash_val: int, dbname: str = "sc_hashes.db") -> Optional[str]:
    dbpath = __get_dbfilepath(dbname)
    if not dbpath:
        return None

    conn = sqlite3.connect(dbpath)
    cur = conn.cursor()

    sql: str = "SELECT symbol_name FROM  symbol_hashes where hash_val = ?"
    value = (hash_val,)

    cur.execute(sql, value)
    result = cur.fetchone()
    cur.close()
    conn.close()

    if not result:
        return "UNKNOWN"

    return result[0].decode()


def __get_dbfilepath(dbname: str) -> Optional[str]:
    script_path: str = os.path.dirname(__file__).replace("/", "\\")
    #####
    # LOAD
    #  1. full path for agurment
    #   => 2. default dbname at malware sample folder
    #   => 3. default dbname at scripts folder
    ######
    if os.path.exists(dbname):
        return dbname
    elif os.path.exists(f"{os.path.dirname(ida_nalt.get_input_file_path())}\\{dbname}"):
        return f"{os.path.dirname(ida_nalt.get_input_file_path())}\\{dbname}"
    elif os.path.exists(f"{script_path}\\{dbname}"):
        return f"{script_path}\\{dbname}"
    else:
        print("[!] Could not found dbfile!!")
    return None


def make_base_struct(struct_name: str = "LODEINFO_API_TABLE") -> int:
    ida_struct.add_struc(0, struct_name)
    id = ida_struct.get_struc_id(struct_name)
    return ida_struct.get_struc(id)


def get_hash_func(
    searchers: List[IFAPIHashSearch], mem: Dict[int, bytes]
) -> Optional[HashFunc]:
    for searcher in searchers:
        hash_func: Optional[HashFunc] = searcher.search(mem)
        if not hash_func:
            continue
        return hash_func


def main():
    st: int = make_base_struct()
    helper: LODEINFO_APIHASH_ANALYZER = LODEINFO_APIHASH_ANALYZER()

    searchers: List[IFAPIHashSearch] = [CRC32Search(), JSHashSearch()]
    hash_func: Optional[HashFunc] = get_hash_func(searchers, helper.mem)

    if not hash_func:
        print("[*] Could not found API Hash function ;(")
        sys.exit(0)
    api_resolve_func_addr: int = helper.search_func_for_resolve_api(hash_func.address)
    xrefs: List[int] = helper.get_xref_addresses(api_resolve_func_addr)

    for i, xref in enumerate(xrefs):
        api_hash: Optional[int] = helper.get_api_hash_value(xref)
        if not api_hash:
            print(f"[!] Could not found API Hash value at [{hex(xref)}]")
            continue
        api_name: Optional[str] = get_apiname_from_hash(api_hash ^ hash_func.xor_key)
        if not api_name:
            print("DB connection faild...")
            break
        status_code: int = ida_struct.add_struc_member(st, api_name, i * 4, idaapi.FF_DWORD, None, 4)
        if status_code == -1:
            ida_struct.add_struc_member(st, f"{api_name}_{hex(i)}", i * 4, idaapi.FF_DWORD, None, 4)
        print(f"Found {api_name}: {hex(api_hash)}")


if __name__ == "__main__":
    main()
