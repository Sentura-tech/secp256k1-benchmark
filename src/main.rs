
/*# 
######### SECP256k1 Key Generation and Verification Benchmark #########

This benchmark measures the performance of SECP256k1 key generation and signature verification operations under different threading scenarios.

## Benchmark Scenarios

### 1. Single-Core Concurrent
- Runs key generation and verification on a single core
- Each iteration:
  - Generates one keypair
  - Performs one signature verification
  - Every third iteration performs two additional verifications
- Measures operations per second for each type

### 2. Two-Core Split
- Uses two dedicated cores:
  - Core 1: Continuously generates keypairs
  - Core 2: Performs verifications on generated keys
- Communication via channels
- Measures throughput for each operation type separately

### 3. Multi-Core (Using Rayon)
- Utilizes all available CPU cores
- Each core performs the complete cycle:
  - Key generation
  - Single verification
  - Double verification (every third iteration)
- Uses work-stealing scheduler for optimal load balancing
- Measures total throughput and per-core performance

## Measurement Methodology
- Each benchmark runs for minimum n seconds to gather sufficient data points
- Records three metrics:
  - Key generation rate
  - Single verification rate
  - Double verification rate
- Reports results as operations per second

## Performance Counters
- Uses atomic counters for thread-safe operation counting
- Measures key generations, single verifications, and double verifications separately
- Provides both aggregate and per-core statistics where applicable

*/

use std::time::Instant;
use secp256k1::{Secp256k1, Message};
use rayon::prelude::*;
use std::thread;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct OpCounts {
    generations: AtomicUsize,
    verifications: AtomicUsize,
    double_verifications: AtomicUsize,
}


fn main() {
    let num_cores = num_cpus::get();
    println!("Number of CPU cores: {}", num_cores);
    let min_duration = std::time::Duration::from_secs(5);  //set duration per run 

    // Single-core benchmark
    println!("\nRunning single-core concurrent benchmark...");
    let (gen_count, verify_count, double_verify_count) = run_single_core_benchmark(min_duration);
    let duration = min_duration.as_secs_f64();
    
    println!("Single-core concurrent performance:");
    println!("Time taken: {:.2?}", min_duration);
    println!("Keys generated per second: {:.2}", gen_count as f64 / duration);
    println!("Single verifications per second: {:.2}", verify_count as f64 / duration);
    println!("Double verifications per second: {:.2}", double_verify_count as f64 / duration);

    // Two-core benchmark
    println!("\nRunning two-core split benchmark...");
    let (gen_count, verify_count, double_verify_count) = run_two_core_benchmark(min_duration);
    
    println!("Two-core split performance:");
    println!("Time taken: {:.2?}", min_duration);
    println!("Keys generated per second: {:.2}", gen_count as f64 / duration);
    println!("Single verifications per second: {:.2}", verify_count as f64 / duration);
    println!("Double verifications per second: {:.2}", double_verify_count as f64 / duration);

    // Multi-core benchmark
    println!("\nRunning multi-core benchmark ({} cores)...", num_cores);
    let counts = run_multi_core_benchmark(min_duration, num_cores);
    
    println!("Multi-core performance:");
    println!("Time taken: {:.2?}", min_duration);
    println!("Total keys generated per second: {:.2}", 
        counts.generations.load(Ordering::Relaxed) as f64 / duration);
    println!("Total single verifications per second: {:.2}", 
        counts.verifications.load(Ordering::Relaxed) as f64 / duration);
    println!("Total double verifications per second: {:.2}", 
        counts.double_verifications.load(Ordering::Relaxed) as f64 / duration);
}

// Function to generate a unique message for each verification
fn generate_unique_message(counter: usize) -> Message {
    let mut msg_bytes = [0u8; 32];
    msg_bytes[0..8].copy_from_slice(&counter.to_le_bytes());
    // Add some randomness to the rest of the message
    for i in 8..32 {
        msg_bytes[i] = (counter >> (i % 8)) as u8;
    }
    Message::from_digest(msg_bytes)
}

fn run_single_core_benchmark(duration: std::time::Duration) -> (usize, usize, usize) {
    let secp = Secp256k1::new();
    let start = Instant::now();
    let mut gen_count = 0;
    let mut verify_count = 0;
    let mut double_verify_count = 0;
    let mut keys = Vec::new();

    while start.elapsed() < duration {
        // Generate a new key and sign a unique message
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        let msg = generate_unique_message(gen_count);
        let signature = secp.sign_ecdsa(&msg, &secret_key);
        keys.push((public_key, signature, msg));
        gen_count += 1;

        // Perform verifications if we have keys
        if !keys.is_empty() {
            let idx = gen_count % keys.len();
            let (pub_key, sig, msg) = &keys[idx];
            
            // Single verification
            secp.verify_ecdsa(msg, sig, pub_key).unwrap();
            verify_count += 1;

            // Double verification (every third iteration to mix operations)
            if gen_count % 3 == 0 {
                secp.verify_ecdsa(msg, sig, pub_key).unwrap();
                secp.verify_ecdsa(msg, sig, pub_key).unwrap();
                double_verify_count += 2;
            }
        }
    }

    (gen_count, verify_count, double_verify_count)
}

fn run_two_core_benchmark(duration: std::time::Duration) -> (usize, usize, usize) {
    let (tx, rx) = channel();

    // Generator thread
    let gen_thread = thread::spawn(move || {
        let secp = Secp256k1::new();
        let start = Instant::now();
        let mut count = 0;
        
        while start.elapsed() < duration {
            let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
            let msg = generate_unique_message(count);
            let signature = secp.sign_ecdsa(&msg, &secret_key);
            tx.send((public_key, signature, msg)).unwrap();
            count += 1;
        }
        count
    });

    // Verifier thread
    let verify_thread = thread::spawn(move || {
        let secp = Secp256k1::new();
        let mut verify_count = 0;
        let mut double_verify_count = 0;
        let mut keys = Vec::new();
        let start = Instant::now();

        while start.elapsed() < duration {
            while let Ok((pub_key, sig, msg)) = rx.try_recv() {
                keys.push((pub_key, sig, msg));
            }

            if !keys.is_empty() {
                let idx = verify_count % keys.len();
                let (pub_key, sig, msg) = &keys[idx];

                // Single verification
                secp.verify_ecdsa(msg, sig, pub_key).unwrap();
                verify_count += 1;

                // Double verification (every third iteration)
                if verify_count % 3 == 0 {
                    secp.verify_ecdsa(msg, sig, pub_key).unwrap();
                    secp.verify_ecdsa(msg, sig, pub_key).unwrap();
                    double_verify_count += 2;
                }
            }
        }
        (verify_count, double_verify_count)
    });

    let gen_count = gen_thread.join().unwrap();
    let (verify_count, double_verify_count) = verify_thread.join().unwrap();
    
    (gen_count, verify_count, double_verify_count)
}

fn run_multi_core_benchmark(duration: std::time::Duration, num_cores: usize) -> Arc<OpCounts> {
    let counts = Arc::new(OpCounts::default());
    
    // Use Rayon's parallel iterator
    (0..num_cores).into_par_iter().for_each(|thread_id| {
        let secp = Secp256k1::new();
        let mut keys = Vec::new();
        let start = Instant::now();
        let mut local_count = 0;
        
        while start.elapsed() < duration {
            // Generate new key with unique message
            let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
            let msg = generate_unique_message(thread_id * 1_000_000 + local_count); // Ensure uniqueness across threads
            let signature = secp.sign_ecdsa(&msg, &secret_key);
            keys.push((public_key, signature, msg));
            counts.generations.fetch_add(1, Ordering::Relaxed);

            // Perform verifications if we have keys
            if !keys.is_empty() {
                let idx = keys.len() - 1;
                let (pub_key, sig, msg) = &keys[idx];

                // Single verification
                secp.verify_ecdsa(msg, sig, pub_key).unwrap();
                counts.verifications.fetch_add(1, Ordering::Relaxed);

                // Double verification (every third iteration)
                if keys.len() % 3 == 0 {
                    secp.verify_ecdsa(msg, sig, pub_key).unwrap();
                    secp.verify_ecdsa(msg, sig, pub_key).unwrap();
                    counts.double_verifications.fetch_add(2, Ordering::Relaxed);
                }
            }
            local_count += 1;
        }
    });

    counts
}
