import ctypes
import sys
import os
import platform

if platform.system() != 'Windows':
    print("Error: run_payload.py only works on Windows.")
    print("       This script uses Windows APIs (VirtualAlloc, CreateThread).")
    sys.exit(1)

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

def run(payload_path):
    with open(payload_path, 'rb') as f:
        payload = f.read()

    print(f"[*] Loaded {len(payload)} bytes from {payload_path}")

    kernel32 = ctypes.windll.kernel32

    VirtualAlloc = kernel32.VirtualAlloc
    VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
    VirtualAlloc.restype = ctypes.c_void_p

    CreateThread = kernel32.CreateThread
    CreateThread.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    CreateThread.restype = ctypes.c_void_p

    ptr = VirtualAlloc(None, len(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not ptr:
        print(f"[-] VirtualAlloc failed: {kernel32.GetLastError()}")
        return

    print(f"[*] Allocated memory at 0x{ptr:016x}")
    ctypes.memmove(ptr, bytes(payload), len(payload))

    thread_id_out = ctypes.c_ulong(0)
    handle = CreateThread(None, 0, ptr, None, 0, ctypes.byref(thread_id_out))
    if not handle:
        print(f"[-] CreateThread failed: {kernel32.GetLastError()}")
        return

    print(f"[*] Created thread {thread_id_out.value}, waiting...")

    WaitForSingleObject = kernel32.WaitForSingleObject
    WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    WaitForSingleObject.restype = ctypes.c_ulong

    WaitForSingleObject(handle, 0xFFFFFFFF)
    print("[*] Done")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_payload = os.path.join(script_dir, "..", "out", "payload.bin")

    payload_path = sys.argv[1] if len(sys.argv) > 1 else default_payload
    run(payload_path)
