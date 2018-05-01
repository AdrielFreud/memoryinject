import sys
from ctypes import *

#./dll_injector <PID> <Path to DLL>

PAGE_READWRITE     =     0x04
PROCESS_ALL_ACCESS =     (0x000F0000 | 0x00100000 | 0xFFF)
VIRTUAL_MEM        =     (0x1000 | 0x2000)
kernel32 = windll.kernel32
pid      = sys.argv[1]
dll_path = sys.argv[2]

dll_len  = len(dll_path)
h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(pid))

if not h_process:
    print("[*] Couldn't acquire a handle to PID: %s"%pid)
    sys.exit(0)

arg_address = kernel32.VirtualAllocEx(h_process, 0, dll_len, VIRTUAL_MEM, PAGE_READWRITE)
written = c_int(0)
kernel32.WriteProcessMemory(h_process, arg_address, dll_path, dll_len, byref(written))
h_kernel32 = kernel32.GetModuleHandleA("kernel32.dll")
h_loadlib  = kernel32.GetProcAddress(h_kernel32,"LoadLibraryA")
thread_id = c_ulong(0)

if not kernel32.CreateRemoteThread(h_process, None, 0, h_loadlib, arg_address, 0, byref(thread_id)):
    print("[*] Failed to inject the DLL. Exiting.")
    sys.exit(0)
print("[*] Remote thread with ID 0x%08x created."%thread_id.value)

