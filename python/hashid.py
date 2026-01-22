#!/usr/bin/env python3
"""
HashID - Hash Type Identifier
Author: bad-antics | GitHub: bad-antics | Discord: discord.gg/killers
License: NCRY-XXX (Get key at discord.gg/killers)

     ▓█████▄  ██▀███   ██▓ ██▓███      ██░ ██  ▄▄▄        ██████  ██░ ██  ██▓▓█████▄ 
     ▒██▀ ██▌▓██ ▒ ██▒▓██▒▓██░  ██▒   ▓██░ ██▒▒████▄    ▒██    ▒ ▓██░ ██▒▓██▒▒██▀ ██▌
     ░██   █▌▓██ ░▄█ ▒▒██▒▓██░ ██▓▒   ▒██▀▀██░▒██  ▀█▄  ░ ▓██▄   ▒██▀▀██░▒██▒░██   █▌
"""

import re
import sys
import argparse
import hashlib
from typing import List, Tuple, Optional
from dataclasses import dataclass

BANNER = """
     ▓█████▄  ██▀███   ██▓ ██▓███      ██░ ██  ▄▄▄        ██████  ██░ ██  ██▓▓█████▄ 
     ▒██▀ ██▌▓██ ▒ ██▒▓██▒▓██░  ██▒   ▓██░ ██▒▒████▄    ▒██    ▒ ▓██░ ██▒▓██▒▒██▀ ██▌
     ░██   █▌▓██ ░▄█ ▒▒██▒▓██░ ██▓▒   ▒██▀▀██░▒██  ▀█▄  ░ ▓██▄   ▒██▀▀██░▒██▒░██   █▌
     ░▓█▄   ▌▒██▀▀█▄  ░██░▒██▄█▓▒ ▒   ░▓█ ░██ ░██▄▄▄▄██   ▒   ██▒░▓█ ░██ ░██░░▓█▄   ▌
     ░▒████▓ ░██▓ ▒██▒░██░▒██▒ ░  ░   ░▓█▒░██▓ ▓█   ▓██▒▒██████▒▒░▓█▒░██▓░██░░▒████▓ 
      ▒▒▓  ▒ ░ ▒▓ ░▒▓░░▓  ▒▓▒░ ░  ░    ▒ ░░▒░▒ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░▓   ▒▒▓  ▒ 
     ═══════════════════════════════════════════════════════════════════════════════
                       HashID v2.0 | github.com/bad-antics
     ═══════════════════════════════════════════════════════════════════════════════
"""


@dataclass
class HashType:
    name: str
    hashcat_mode: int
    john_format: str
    regex: str
    description: str


# Hash type definitions
HASH_TYPES = [
    # Raw hashes
    HashType("MD5", 0, "raw-md5", r"^[a-f0-9]{32}$", "MD5 raw hash"),
    HashType("SHA1", 100, "raw-sha1", r"^[a-f0-9]{40}$", "SHA1 raw hash"),
    HashType("SHA256", 1400, "raw-sha256", r"^[a-f0-9]{64}$", "SHA256 raw hash"),
    HashType("SHA512", 1700, "raw-sha512", r"^[a-f0-9]{128}$", "SHA512 raw hash"),
    HashType("SHA384", 10800, "raw-sha384", r"^[a-f0-9]{96}$", "SHA384 raw hash"),
    HashType("NTLM", 1000, "nt", r"^[a-f0-9]{32}$", "NTLM (Windows)"),
    HashType("LM", 3000, "lm", r"^[a-f0-9]{32}$", "LM (Windows Legacy)"),
    
    # Unix hashes
    HashType("MD5crypt", 500, "md5crypt", r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$", "MD5crypt (Unix)"),
    HashType("SHA256crypt", 7400, "sha256crypt", r"^\$5\$[a-zA-Z0-9./]{16}\$[a-zA-Z0-9./]{43}$", "SHA256crypt (Unix)"),
    HashType("SHA512crypt", 1800, "sha512crypt", r"^\$6\$[a-zA-Z0-9./]{16}\$[a-zA-Z0-9./]{86}$", "SHA512crypt (Unix)"),
    HashType("bcrypt", 3200, "bcrypt", r"^\$2[aby]?\$[0-9]{2}\$[a-zA-Z0-9./]{53}$", "bcrypt"),
    HashType("scrypt", 8900, "scrypt", r"^\$scrypt\$", "scrypt"),
    HashType("Argon2", 0, "argon2", r"^\$argon2(i|d|id)\$", "Argon2"),
    
    # Web/Application hashes
    HashType("WordPress", 400, "phpass", r"^\$P\$[a-zA-Z0-9./]{31}$", "WordPress/phpBB3"),
    HashType("Drupal7", 7900, "drupal7", r"^\$S\$[a-zA-Z0-9./]{52}$", "Drupal 7"),
    HashType("Django PBKDF2-SHA256", 10000, "django", r"^pbkdf2_sha256\$[0-9]+\$[a-zA-Z0-9+/]+\$[a-zA-Z0-9+/]+=*$", "Django PBKDF2"),
    
    # Database hashes
    HashType("MySQL 4.1+", 300, "mysql-sha1", r"^\*[A-F0-9]{40}$", "MySQL 4.1+ (double SHA1)"),
    HashType("MySQL 3.x", 200, "mysql", r"^[a-f0-9]{16}$", "MySQL 3.x"),
    HashType("PostgreSQL MD5", 0, "postgres", r"^md5[a-f0-9]{32}$", "PostgreSQL MD5"),
    HashType("MSSQL 2005", 132, "mssql05", r"^0x0100[a-f0-9]{48}$", "MSSQL 2005"),
    HashType("MSSQL 2012+", 1731, "mssql12", r"^0x0200[a-f0-9]{136}$", "MSSQL 2012/2014"),
    HashType("Oracle 11g", 112, "oracle11", r"^S:[A-F0-9]{60}$", "Oracle 11g"),
    
    # Network hashes
    HashType("NetNTLMv1", 5500, "netntlm", r"^[a-zA-Z0-9]+::[a-zA-Z0-9]+:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]+$", "NetNTLMv1"),
    HashType("NetNTLMv2", 5600, "netntlmv2", r"^[a-zA-Z0-9]+::[a-zA-Z0-9]+:[a-f0-9]{16}:[a-f0-9]{32}:[a-f0-9]+$", "NetNTLMv2"),
    HashType("Kerberos 5 TGS-REP", 13100, "krb5tgs", r"^\$krb5tgs\$[0-9]+\$", "Kerberos 5 TGS-REP"),
    HashType("Kerberos 5 AS-REP", 18200, "krb5asrep", r"^\$krb5asrep\$[0-9]+\$", "Kerberos 5 AS-REP (Roast)"),
    
    # Wireless hashes
    HashType("WPA/WPA2", 22000, "wpapsk", r"^[a-f0-9]{64}$", "WPA/WPA2 PSK (raw PMK)"),
    HashType("WPA-PMKID", 22000, "wpapsk-pmkid", r"^[a-f0-9]{32}\*[a-f0-9]{12}\*[a-f0-9]{12}\*[a-f0-9]+$", "WPA PMKID"),
    
    # Cryptocurrency
    HashType("Bitcoin/Litecoin", 11300, "bitcoin", r"^\$bitcoin\$[0-9]+\$", "Bitcoin/Litecoin wallet"),
    HashType("Ethereum Wallet", 15600, "ethereum", r"^\$ethereum\$", "Ethereum wallet"),
    
    # Archive hashes
    HashType("RAR3", 12500, "rar3", r"^\$RAR3\$", "RAR3-hp"),
    HashType("RAR5", 13000, "rar5", r"^\$rar5\$", "RAR5"),
    HashType("7-Zip", 11600, "7z", r"^\$7z\$", "7-Zip"),
    HashType("ZIP", 13600, "zip", r"^\$zip2\$", "ZIP"),
    HashType("PDF", 10500, "pdf", r"^\$pdf\$", "PDF"),
    
    # JWT
    HashType("JWT HS256", 16500, "jwt", r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", "JWT (JSON Web Token)"),
    
    # API Keys / Tokens
    HashType("AWS Access Key", 0, "", r"^AKIA[0-9A-Z]{16}$", "AWS Access Key ID"),
    HashType("GitHub Token", 0, "", r"^gh[pousr]_[A-Za-z0-9_]{36,}$", "GitHub Personal Access Token"),
]


def identify_hash(hash_string: str) -> List[HashType]:
    """Identify possible hash types for a given string."""
    hash_string = hash_string.strip()
    matches = []
    
    for hash_type in HASH_TYPES:
        if re.match(hash_type.regex, hash_string, re.IGNORECASE):
            matches.append(hash_type)
    
    return matches


def analyze_hash(hash_string: str) -> dict:
    """Detailed analysis of a hash string."""
    hash_string = hash_string.strip()
    
    analysis = {
        'hash': hash_string,
        'length': len(hash_string),
        'charset': set(hash_string.lower()),
        'is_hex': all(c in '0123456789abcdef' for c in hash_string.lower()),
        'is_base64': bool(re.match(r'^[A-Za-z0-9+/]+=*$', hash_string)),
        'has_salt': ':' in hash_string or '$' in hash_string,
        'prefix': None,
    }
    
    # Extract prefix for salted hashes
    if hash_string.startswith('$'):
        parts = hash_string.split('$')
        if len(parts) >= 2:
            analysis['prefix'] = f"${parts[1]}$"
    
    return analysis


def print_results(hash_string: str, matches: List[HashType], verbose: bool = False):
    """Print identification results."""
    print(f"\n[*] Analyzing: {hash_string[:60]}{'...' if len(hash_string) > 60 else ''}")
    print(f"[*] Length: {len(hash_string)}")
    
    if not matches:
        print("[-] No matching hash types found")
        return
    
    print(f"[+] Found {len(matches)} possible type(s):\n")
    
    for i, match in enumerate(matches, 1):
        print(f"  {i}. {match.name}")
        if verbose:
            print(f"     Description: {match.description}")
            print(f"     Hashcat mode: {match.hashcat_mode}")
            print(f"     John format: {match.john_format}")
        print()


def generate_test_hash(algorithm: str, password: str = "password") -> Optional[str]:
    """Generate a test hash for verification."""
    algo_map = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
        'sha384': hashlib.sha384,
    }
    
    if algorithm.lower() in algo_map:
        return algo_map[algorithm.lower()](password.encode()).hexdigest()
    return None


def process_file(filepath: str, verbose: bool = False) -> dict:
    """Process a file containing hashes."""
    results = {}
    
    try:
        with open(filepath, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Handle hash:salt or user:hash formats
                if ':' in line and not line.startswith('$'):
                    parts = line.split(':')
                    hash_string = parts[0] if len(parts[0]) > len(parts[-1]) else parts[-1]
                else:
                    hash_string = line
                
                matches = identify_hash(hash_string)
                
                if matches:
                    type_name = matches[0].name
                    if type_name not in results:
                        results[type_name] = {
                            'count': 0,
                            'hashcat_mode': matches[0].hashcat_mode,
                            'john_format': matches[0].john_format,
                            'samples': []
                        }
                    results[type_name]['count'] += 1
                    if len(results[type_name]['samples']) < 3:
                        results[type_name]['samples'].append(hash_string)
                        
    except FileNotFoundError:
        print(f"[-] File not found: {filepath}")
        sys.exit(1)
    
    return results


def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description='NullSec Hash Identifier',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 hashid.py 5d41402abc4b2a76b9719d911017c592
  python3 hashid.py -f hashes.txt
  python3 hashid.py -f hashes.txt -v
  python3 hashid.py --test md5

Get premium at discord.gg/killers
        '''
    )
    
    parser.add_argument('hash', nargs='?', help='Hash string to identify')
    parser.add_argument('-f', '--file', help='File containing hashes')
    parser.add_argument('-v', '--verbose', action='store_true', 
                        help='Verbose output with hashcat/john info')
    parser.add_argument('--test', metavar='ALGO',
                        help='Generate test hash (md5, sha1, sha256, etc.)')
    parser.add_argument('--version', action='store_true', help='Show version')
    
    args = parser.parse_args()
    
    if args.version:
        print("HashID v2.0.0")
        print("github.com/bad-antics | discord.gg/killers")
        return
    
    if args.test:
        test_hash = generate_test_hash(args.test)
        if test_hash:
            print(f"[+] Test {args.test.upper()} hash of 'password':")
            print(f"    {test_hash}")
        else:
            print(f"[-] Unknown algorithm: {args.test}")
        return
    
    if args.file:
        print(f"[*] Processing file: {args.file}")
        results = process_file(args.file, args.verbose)
        
        if not results:
            print("[-] No valid hashes found")
            return
        
        print("\n" + "═" * 60)
        print("SUMMARY")
        print("═" * 60)
        
        total = sum(r['count'] for r in results.values())
        
        for type_name, data in sorted(results.items(), key=lambda x: -x[1]['count']):
            pct = (data['count'] / total) * 100
            print(f"\n[+] {type_name}: {data['count']} ({pct:.1f}%)")
            print(f"    Hashcat: -m {data['hashcat_mode']}")
            print(f"    John: --format={data['john_format']}")
            print(f"    Samples:")
            for sample in data['samples']:
                print(f"      {sample[:50]}{'...' if len(sample) > 50 else ''}")
        
        print(f"\n[*] Total hashes: {total}")
        
    elif args.hash:
        matches = identify_hash(args.hash)
        print_results(args.hash, matches, args.verbose)
        
        if matches and args.verbose:
            analysis = analyze_hash(args.hash)
            print("[*] Analysis:")
            print(f"    Is hex: {analysis['is_hex']}")
            print(f"    Is base64: {analysis['is_base64']}")
            print(f"    Has salt: {analysis['has_salt']}")
            if analysis['prefix']:
                print(f"    Prefix: {analysis['prefix']}")
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
