# secp256k1-benchmark
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

