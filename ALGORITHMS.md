# NullSec Crypto - Algorithm Reference

## Symmetric Encryption

### AES
```bash
# Encrypt file
nullsec-crypto --encrypt --algo aes-256-gcm --key secret.key -i plain.txt -o encrypted.bin

# Decrypt file
nullsec-crypto --decrypt --algo aes-256-gcm --key secret.key -i encrypted.bin -o plain.txt
```

### ChaCha20
```bash
nullsec-crypto --encrypt --algo chacha20-poly1305 --key secret.key -i data.bin -o encrypted.bin
```

## Asymmetric Encryption

### RSA
```bash
# Generate key pair
nullsec-crypto --genkey --algo rsa --bits 4096 -o keypair

# Encrypt with public key
nullsec-crypto --encrypt --algo rsa --pubkey public.pem -i secret.txt -o encrypted.bin

# Decrypt with private key
nullsec-crypto --decrypt --algo rsa --privkey private.pem -i encrypted.bin -o secret.txt
```

### ECC (Elliptic Curve)
```bash
# Generate ECDSA key
nullsec-crypto --genkey --algo ecdsa --curve secp256k1 -o keypair

# Sign message
nullsec-crypto --sign --algo ecdsa --privkey private.pem -i message.txt -o signature.bin

# Verify signature
nullsec-crypto --verify --algo ecdsa --pubkey public.pem -i message.txt --sig signature.bin
```

## Hashing

### Standard Hashes
```bash
# MD5 (insecure, for compatibility)
nullsec-crypto --hash --algo md5 -i file.bin

# SHA-256
nullsec-crypto --hash --algo sha256 -i file.bin

# SHA-3
nullsec-crypto --hash --algo sha3-256 -i file.bin

# BLAKE3 (fast)
nullsec-crypto --hash --algo blake3 -i file.bin
```

### Password Hashing
```bash
# Argon2id (recommended)
nullsec-crypto --hash --algo argon2id --password "secret" --memory 65536 --iterations 3

# bcrypt
nullsec-crypto --hash --algo bcrypt --password "secret" --cost 12

# scrypt
nullsec-crypto --hash --algo scrypt --password "secret" --n 16384 --r 8 --p 1
```

## Key Derivation

```bash
# PBKDF2
nullsec-crypto --derive --algo pbkdf2 --password "secret" --salt random --iterations 100000

# HKDF
nullsec-crypto --derive --algo hkdf --ikm master.key --info "encryption" --length 32
```

## Analysis Tools

```bash
# Identify cipher
nullsec-crypto --analyze --identify -i encrypted.bin

# Entropy analysis
nullsec-crypto --analyze --entropy -i data.bin

# Frequency analysis
nullsec-crypto --analyze --frequency -i ciphertext.txt
```
