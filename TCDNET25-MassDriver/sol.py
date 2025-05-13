import ctypes
import struct

# Wrong fields and value
magic1 = b'WRONGWORD:'
magic2 = b'"|WRONG_TIME:"'
data1  = b'ENGINE_WRONG'

# Reversed fields and value
#magic1 = b'PASSWORD:'
#magic2 = b'"|ENGINE_BOOT_TIME:"'
#data1  = b'ENGINE_1337_GO'
payload = magic1 + data1 + b"|" + magic2 + b"B" * 8  # <-- Padding added after magic2

# Constants
device_path = r"\\.\MassDriverDeviceLink"
GENERIC_READ  = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
MAGIC_INSTRUCTION = 0x13372000 # Branch 2
# MAGIC_INSTRUCTION = 0x220004a4 # Branch 1?
# MAGIC_INSTRUCTION = 0x11111111 # Branch 3 (Default-Fail)

# Windows APIs
CreateFile = ctypes.windll.kernel32.CreateFileW
DeviceIoControl = ctypes.windll.kernel32.DeviceIoControl
CloseHandle = ctypes.windll.kernel32.CloseHandle

# Open handle
hDevice = CreateFile(device_path, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
if hDevice == -1 or hDevice == 0xFFFFFFFF:
    print("[!] Failed to open device.")
    exit(1)

print("[+] Opened handle to MassDriver.")

# Allocate buffer
out_buffer = ctypes.create_string_buffer(0x1000)
bytes_returned = ctypes.c_ulong(0)

# Send IOCTL
success = DeviceIoControl(
    hDevice,
    MAGIC_INSTRUCTION,
    payload,
    len(payload),
    out_buffer,
    ctypes.sizeof(out_buffer),
    ctypes.byref(bytes_returned),
    None
)

if success:
    print("[+] Device responded:")
    print(out_buffer.raw[:bytes_returned.value])
    print(out_buffer.raw[:bytes_returned.value].decode(errors="ignore"))
else:
    print("[!] DeviceIoControl failed.")

CloseHandle(hDevice)
