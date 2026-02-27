<!-- 
SEO Keywords: NullSec Crypto, cryptography tools, hash cracker, password cracker,
encryption tools, decryption, AES cracker, MD5 cracker, SHA256 cracker, bcrypt cracker,
bad-antics, NullSec Framework, crypto analysis, rainbow tables, hash identifier
-->

<div align="center">

# 🔐 NullSec Crypto

### Advanced Cryptography & Hash Analysis Toolkit

[![X/Twitter](https://img.shields.io/badge/🔑_GET_KEYS-x.com/AnonAntics-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://x.com/AnonAntics)
[![GitHub](https://img.shields.io/badge/GitHub-bad--antics-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/bad-antics)
[![License](https://img.shields.io/badge/License-NCRY--XXX-red?style=for-the-badge)](LICENSE)

[![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)]()
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)]()
[![C](https://img.shields.io/badge/C-A8B9CC?style=for-the-badge&logo=c&logoColor=black)]()
[![Crystal](https://img.shields.io/badge/Crystal-000000?style=for-the-badge&logo=crystal&logoColor=white)]()

```
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ░ ▒░   ▒ ▒ ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░▓  ░▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ░▒ ▒  ░
     ░    ░    ░   ░   ░         ░            ░   ░   ░        
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░░░░ C R Y P T O ░░░░░░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics
```

### 🔓 **[Join x.com/AnonAntics](https://x.com/AnonAntics)** for premium features!

</div>

---

## 🎯 Features

| Tool | Language | Description | Free | Premium |
|------|----------|-------------|------|---------|
| **hashcrack** | Rust | GPU-accelerated hash cracker | ✅ | 🔥 |
| **hashid** | Python | Hash type identifier | ✅ | 🔥 |
| **cryptor** | Rust | AES/ChaCha encryption tool | ✅ | 🔥 |
| **keyanalyze** | C | Cryptographic key analyzer | ❌ | 🔥 |
| **rainbow** | Rust | Rainbow table generator | ❌ | 🔥 |
| **jwtcrack** | Python | JWT token analyzer/cracker | ✅ | 🔥 |

---

## 📁 Structure

```
nullsec-crypto/
├── rust/
│   ├── hashcrack/       # Multi-threaded hash cracker
│   ├── cryptor/         # Encryption/decryption tool
│   └── rainbow/         # Rainbow table generator
├── c/
│   ├── keyanalyze.c     # Key strength analyzer
│   └── entropy.c        # Entropy calculator
├── python/
│   ├── hashid.py        # Hash identifier
│   ├── jwtcrack.py      # JWT analyzer
│   └── b64crack.py      # Base64 decoder/analyzer
└── wordlists/
    └── README.md        # Wordlist sources
```

---

## 🚀 Supported Hash Types

| Algorithm | Speed (CPU) | Speed (GPU) | Status |
|-----------|-------------|-------------|--------|
| MD5 | 50M/s | 25B/s | ✅ |
| SHA1 | 30M/s | 15B/s | ✅ |
| SHA256 | 15M/s | 8B/s | ✅ |
| SHA512 | 5M/s | 2B/s | ✅ |
| bcrypt | 25K/s | 100K/s | ✅ |
| scrypt | 10K/s | 50K/s | ✅ |
| Argon2 | 5K/s | 20K/s | ✅ |
| NTLM | 80M/s | 40B/s | ✅ |
| WPA2 | 500/s | 500K/s | 🔥 Premium |

---

## 🔧 Quick Start

```bash
# Identify hash type
python3 hashid.py -f hashes.txt

# Crack hashes with wordlist
./hashcrack -m md5 -w rockyou.txt hashes.txt

# Crack with rules
./hashcrack -m sha256 -w wordlist.txt -r best64.rule hashes.txt

# Encrypt file
./cryptor encrypt -i secret.txt -o secret.enc -p "password"

# Decrypt file
./cryptor decrypt -i secret.enc -o secret.txt -p "password"
```

---

## ⚠️ Legal Disclaimer

**For authorized security testing only.** Only crack hashes you have permission to test.

---

<div align="center">

**NullSec Framework** | [GitHub](https://github.com/bad-antics) | [X/Twitter](https://x.com/AnonAntics)

</div>
