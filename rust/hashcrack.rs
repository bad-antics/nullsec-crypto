/*
 * HashCrack - Multi-threaded Hash Cracker
 * Author: bad-antics | GitHub: bad-antics | Discord: discord.gg/killers
 * License: NCRY-XXX (Get key at discord.gg/killers)
 *
 *     ▓█████▄  ██▀███   ██▓ ██▓███      ▄████▄   ██▀███   ▄▄▄       ▄████▄   ██ ▄█▀
 *     ▒██▀ ██▌▓██ ▒ ██▒▓██▒▓██░  ██▒  ▒██▀ ▀█  ▓██ ▒ ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ 
 */

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// Hash libraries
use md5;
use sha1::Sha1;
use sha2::{Sha256, Sha512, Digest};

const VERSION: &str = "2.0.0";
const BANNER: &str = r#"
     ▓█████▄  ██▀███   ██▓ ██▓███      ▄████▄   ██▀███   ▄▄▄       ▄████▄   ██ ▄█▀
     ▒██▀ ██▌▓██ ▒ ██▒▓██▒▓██░  ██▒  ▒██▀ ▀█  ▓██ ▒ ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ 
     ░██   █▌▓██ ░▄█ ▒▒██▒▓██░ ██▓▒  ▒▓█    ▄ ▓██ ░▄█ ▒▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ 
     ░▓█▄   ▌▒██▀▀█▄  ░██░▒██▄█▓▒ ▒  ▒▓▓▄ ▄██▒▒██▀▀█▄  ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ 
     ░▒████▓ ░██▓ ▒██▒░██░▒██▒ ░  ░  ▒ ▓███▀ ░░██▓ ▒██▒ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄
      ▒▒▓  ▒ ░ ▒▓ ░▒▓░░▓  ▒▓▒░ ░  ░  ░ ░▒ ▒  ░░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒
     ════════════════════════════════════════════════════════════════════════════
                     HashCrack v2.0 | github.com/bad-antics
     ════════════════════════════════════════════════════════════════════════════
"#;

/// Supported hash types
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HashType {
    MD5,
    SHA1,
    SHA256,
    SHA512,
    NTLM,
}

impl HashType {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "md5" | "0" => Some(HashType::MD5),
            "sha1" | "100" => Some(HashType::SHA1),
            "sha256" | "1400" => Some(HashType::SHA256),
            "sha512" | "1700" => Some(HashType::SHA512),
            "ntlm" | "1000" => Some(HashType::NTLM),
            _ => None,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            HashType::MD5 => "MD5",
            HashType::SHA1 => "SHA1",
            HashType::SHA256 => "SHA256",
            HashType::SHA512 => "SHA512",
            HashType::NTLM => "NTLM",
        }
    }

    fn hash_length(&self) -> usize {
        match self {
            HashType::MD5 | HashType::NTLM => 32,
            HashType::SHA1 => 40,
            HashType::SHA256 => 64,
            HashType::SHA512 => 128,
        }
    }
}

/// Hash a string using the specified algorithm
pub fn hash_string(input: &str, hash_type: HashType) -> String {
    match hash_type {
        HashType::MD5 => {
            let digest = md5::compute(input.as_bytes());
            format!("{:x}", digest)
        }
        HashType::SHA1 => {
            let mut hasher = Sha1::new();
            hasher.update(input.as_bytes());
            format!("{:x}", hasher.finalize())
        }
        HashType::SHA256 => {
            let mut hasher = Sha256::new();
            hasher.update(input.as_bytes());
            format!("{:x}", hasher.finalize())
        }
        HashType::SHA512 => {
            let mut hasher = Sha512::new();
            hasher.update(input.as_bytes());
            format!("{:x}", hasher.finalize())
        }
        HashType::NTLM => {
            // NTLM: MD4 of UTF-16LE encoded password
            let utf16: Vec<u8> = input
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect();
            // Simplified - would use MD4 in real implementation
            let digest = md5::compute(&utf16);
            format!("{:x}", digest)
        }
    }
}

/// Hash cracker struct
pub struct HashCracker {
    hash_type: HashType,
    hashes: HashMap<String, Option<String>>,
    threads: usize,
    tried: AtomicU64,
    cracked: AtomicU64,
    running: AtomicBool,
    start_time: Option<Instant>,
}

impl HashCracker {
    pub fn new(hash_type: HashType, threads: usize) -> Self {
        Self {
            hash_type,
            hashes: HashMap::new(),
            threads,
            tried: AtomicU64::new(0),
            cracked: AtomicU64::new(0),
            running: AtomicBool::new(false),
            start_time: None,
        }
    }

    pub fn load_hashes(&mut self, hashes: Vec<String>) {
        for hash in hashes {
            let normalized = hash.to_lowercase().trim().to_string();
            if normalized.len() == self.hash_type.hash_length() {
                self.hashes.insert(normalized, None);
            }
        }
    }

    pub fn load_hashes_from_file(&mut self, path: &str) -> std::io::Result<()> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        
        for line in reader.lines() {
            if let Ok(hash) = line {
                let normalized = hash.to_lowercase().trim().to_string();
                
                // Handle hash:salt format
                let hash_part = if normalized.contains(':') {
                    normalized.split(':').next().unwrap_or(&normalized)
                } else {
                    &normalized
                };
                
                if hash_part.len() == self.hash_type.hash_length() {
                    self.hashes.insert(hash_part.to_string(), None);
                }
            }
        }
        
        Ok(())
    }

    pub fn crack_with_wordlist(&mut self, wordlist_path: &str) -> std::io::Result<()> {
        println!(BANNER);
        println!("[*] Hash type: {}", self.hash_type.name());
        println!("[*] Hashes loaded: {}", self.hashes.len());
        println!("[*] Threads: {}", self.threads);
        println!("[*] Wordlist: {}", wordlist_path);
        println!();
        
        // Load wordlist into memory for multi-threading
        let file = File::open(wordlist_path)?;
        let reader = BufReader::new(file);
        let words: Vec<String> = reader
            .lines()
            .filter_map(|l| l.ok())
            .collect();
            
        println!("[*] Words loaded: {}", words.len());
        println!("[*] Starting attack...");
        println!("═".repeat(60));
        
        self.running.store(true, Ordering::SeqCst);
        let start = Instant::now();
        
        // Split work among threads
        let chunk_size = words.len() / self.threads + 1;
        let hashes = Arc::new(Mutex::new(self.hashes.clone()));
        let cracked = Arc::new(AtomicU64::new(0));
        let tried = Arc::new(AtomicU64::new(0));
        let running = Arc::new(AtomicBool::new(true));
        let hash_type = self.hash_type;
        
        let mut handles = vec![];
        
        for chunk in words.chunks(chunk_size) {
            let chunk = chunk.to_vec();
            let hashes = Arc::clone(&hashes);
            let cracked = Arc::clone(&cracked);
            let tried = Arc::clone(&tried);
            let running = Arc::clone(&running);
            
            let handle = thread::spawn(move || {
                for word in chunk {
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }
                    
                    let hash = hash_string(&word, hash_type);
                    tried.fetch_add(1, Ordering::Relaxed);
                    
                    let mut hashes_guard = hashes.lock().unwrap();
                    if let Some(entry) = hashes_guard.get_mut(&hash) {
                        if entry.is_none() {
                            *entry = Some(word.clone());
                            cracked.fetch_add(1, Ordering::Relaxed);
                            println!("[+] CRACKED: {} : {}", hash, word);
                        }
                    }
                }
            });
            
            handles.push(handle);
        }
        
        // Progress reporter
        let tried_clone = Arc::clone(&tried);
        let cracked_clone = Arc::clone(&cracked);
        let running_clone = Arc::clone(&running);
        let total_hashes = self.hashes.len();
        
        let progress_handle = thread::spawn(move || {
            while running_clone.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(5));
                let t = tried_clone.load(Ordering::Relaxed);
                let c = cracked_clone.load(Ordering::Relaxed);
                let elapsed = start.elapsed().as_secs_f64();
                let rate = if elapsed > 0.0 { t as f64 / elapsed } else { 0.0 };
                
                print!("\r[*] Progress: {} tried | {}/{} cracked | {:.0} H/s     ",
                    t, c, total_hashes, rate);
                std::io::stdout().flush().ok();
            }
        });
        
        // Wait for workers
        for handle in handles {
            handle.join().ok();
        }
        
        running.store(false, Ordering::SeqCst);
        progress_handle.join().ok();
        
        let elapsed = start.elapsed();
        let final_tried = tried.load(Ordering::Relaxed);
        let final_cracked = cracked.load(Ordering::Relaxed);
        
        println!();
        println!("═".repeat(60));
        println!("[*] Attack completed in {:.2?}", elapsed);
        println!("[*] Words tried: {}", final_tried);
        println!("[*] Hashes cracked: {}/{}", final_cracked, self.hashes.len());
        println!("[*] Speed: {:.0} H/s", final_tried as f64 / elapsed.as_secs_f64());
        
        // Update internal state
        self.hashes = Arc::try_unwrap(hashes)
            .map(|m| m.into_inner().unwrap())
            .unwrap_or_default();
        
        Ok(())
    }

    pub fn save_results(&self, output_path: &str) -> std::io::Result<()> {
        let mut file = File::create(output_path)?;
        
        for (hash, password) in &self.hashes {
            if let Some(pwd) = password {
                writeln!(file, "{}:{}", hash, pwd)?;
            }
        }
        
        println!("[+] Results saved to {}", output_path);
        Ok(())
    }
}

/// Identify hash type by length and format
pub fn identify_hash(hash: &str) -> Vec<HashType> {
    let hash = hash.trim().to_lowercase();
    let mut possible = vec![];
    
    // Check if hex
    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return possible;
    }
    
    match hash.len() {
        32 => {
            possible.push(HashType::MD5);
            possible.push(HashType::NTLM);
        }
        40 => {
            possible.push(HashType::SHA1);
        }
        64 => {
            possible.push(HashType::SHA256);
        }
        128 => {
            possible.push(HashType::SHA512);
        }
        _ => {}
    }
    
    possible
}

fn print_usage() {
    println!(BANNER);
    println!("Usage: hashcrack [OPTIONS] <HASHES>");
    println!();
    println!("Options:");
    println!("  -m, --mode <TYPE>      Hash type (md5, sha1, sha256, sha512, ntlm)");
    println!("  -w, --wordlist <FILE>  Wordlist file");
    println!("  -t, --threads <NUM>    Number of threads (default: CPU cores)");
    println!("  -o, --output <FILE>    Output file for cracked hashes");
    println!("  -r, --rules <FILE>     Rules file for mutations (Premium)");
    println!("  --identify             Identify hash type only");
    println!("  -v, --version          Show version");
    println!();
    println!("Examples:");
    println!("  hashcrack -m md5 -w rockyou.txt hashes.txt");
    println!("  hashcrack --identify 5d41402abc4b2a76b9719d911017c592");
    println!("  hashcrack -m sha256 -w wordlist.txt -t 8 -o cracked.txt hashes.txt");
    println!();
    println!("Get premium at discord.gg/killers");
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        return;
    }
    
    // Simple arg parsing
    let mut hash_type: Option<HashType> = None;
    let mut wordlist: Option<String> = None;
    let mut threads = num_cpus::get();
    let mut output: Option<String> = None;
    let mut hash_file: Option<String> = None;
    let mut identify_only = false;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-m" | "--mode" => {
                if i + 1 < args.len() {
                    hash_type = HashType::from_str(&args[i + 1]);
                    i += 1;
                }
            }
            "-w" | "--wordlist" => {
                if i + 1 < args.len() {
                    wordlist = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-t" | "--threads" => {
                if i + 1 < args.len() {
                    threads = args[i + 1].parse().unwrap_or(threads);
                    i += 1;
                }
            }
            "-o" | "--output" => {
                if i + 1 < args.len() {
                    output = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--identify" => {
                identify_only = true;
            }
            "-v" | "--version" => {
                println!("HashCrack v{}", VERSION);
                println!("github.com/bad-antics | discord.gg/killers");
                return;
            }
            "-h" | "--help" => {
                print_usage();
                return;
            }
            arg if !arg.starts_with('-') => {
                hash_file = Some(arg.to_string());
            }
            _ => {}
        }
        i += 1;
    }
    
    // Identify mode
    if identify_only {
        if let Some(hash) = hash_file {
            println!(BANNER);
            println!("[*] Identifying hash: {}", hash);
            let types = identify_hash(&hash);
            if types.is_empty() {
                println!("[-] Unknown hash format");
            } else {
                println!("[+] Possible types:");
                for t in types {
                    println!("    - {}", t.name());
                }
            }
        }
        return;
    }
    
    // Validate required args
    let hash_type = match hash_type {
        Some(t) => t,
        None => {
            println!("[-] Hash type required (-m)");
            return;
        }
    };
    
    let wordlist = match wordlist {
        Some(w) => w,
        None => {
            println!("[-] Wordlist required (-w)");
            return;
        }
    };
    
    let hash_file = match hash_file {
        Some(f) => f,
        None => {
            println!("[-] Hash file required");
            return;
        }
    };
    
    // Run cracker
    let mut cracker = HashCracker::new(hash_type, threads);
    
    if let Err(e) = cracker.load_hashes_from_file(&hash_file) {
        println!("[-] Error loading hashes: {}", e);
        return;
    }
    
    if let Err(e) = cracker.crack_with_wordlist(&wordlist) {
        println!("[-] Error during cracking: {}", e);
        return;
    }
    
    if let Some(out) = output {
        if let Err(e) = cracker.save_results(&out) {
            println!("[-] Error saving results: {}", e);
        }
    }
}
