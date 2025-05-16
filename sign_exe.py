import subprocess
import os
import sys
from shutil import which

def check_and_install_osslsigncode():
    if which("osslsigncode") is None:
        print("[*] osslsigncode not found, installing...")
        subprocess.run(["sudo", "apt", "update"], check=True)
        subprocess.run(["sudo", "apt", "install", "-y", "osslsigncode"], check=True)
    else:
        print("[+] osslsigncode is already installed.")

def generate_cert_files():
    print("[*] Generating the private key and self-signed certificate...")
    subprocess.run([
        "openssl", "req", "-new", "-newkey", "rsa:2048",
        "-x509", "-days", "365", "-nodes",
        "-subj", "/CN=Anonymous/O=Anonymous/C=FR",
        "-keyout", "anon_key.pem", "-out", "anon_cert.pem"
    ], check=True)

    print("[*] Converting to .pfx format without a password...")
    subprocess.run([
        "openssl", "pkcs12", "-export",
        "-out", "anon_cert.pfx",
        "-inkey", "anon_key.pem",
        "-in", "anon_cert.pem",
        "-passout", "pass:"
    ], check=True)

def sign_exe(file_path, output_file):
    if not os.path.exists(file_path):
        print(f"[-] The file {file_path} does not exist.")
        sys.exit(1)

    if os.path.exists(output_file):
        print(f"[!] Output file {output_file} already exists. Deleting it.")
        os.remove(output_file)

    print(f"[*] Signing {file_path} → {output_file}")

    subprocess.run([
        "osslsigncode", "sign",
        "-pkcs12", "anon_cert.pfx",
        "-pass", "",
        "-n", "Anonymous App",
        "-i", "https://anonymous.url",
        "-t", "http://timestamp.sectigo.com",
        "-in", file_path,
        "-out", output_file
    ], check=True)

    print(f"[+] Signing completed. Output file: {output_file}")

def cleanup_files():
    for f in ["anon_cert.pem", "anon_key.pem", "anon_cert.pfx"]:
        if os.path.exists(f):
            os.remove(f)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 signer.py input.exe [--output custom_name.exe] [--keep]")
        sys.exit(1)

    input_file = None
    output_file = None
    keep_files = False

    for i, arg in enumerate(sys.argv[1:]):
        if arg.endswith(".exe") and input_file is None:
            input_file = arg
        elif arg == "--keep":
            keep_files = True
        elif arg == "--output":
            try:
                output_file = sys.argv[i + 2]
            except IndexError:
                print("[-] Missing output filename after --output.")
                sys.exit(1)

    if not input_file:
        print("[-] No input .exe file provided.")
        sys.exit(1)

    if not output_file:
        output_file = input_file.replace(".exe", "_signed.exe")

    check_and_install_osslsigncode()
    generate_cert_files()
    sign_exe(input_file, output_file)

    if not keep_files:
        cleanup_files()

    # Replace original file with signed version
    try:
        os.remove(input_file)  # Delete original
        os.rename(output_file, input_file)  # Rename signed file to original name
        print(f"[+] Replaced original {input_file} with signed version.")
    except Exception as e:
        print(f"[!] Failed to replace original file: {e}")
