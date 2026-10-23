# Cryptography & Quantum Attacks Assignment
**Course**: Cryptography (CYG) — 7th Semester  
**Institution**: ABV - Indian Institute of Information Technology and Management, Gwalior (ABV-IIITM Gwalior)  

---

## 📁 Repository & Project Structure

```
Assignment/
├── Makefile                     # Build automation for C and Python targets
├── README.md                    # Project documentation & run guide
├── pyrightconfig.json           # IDE & Language Server configuration
├── src/
│   ├── c/                       # Classical Cryptosystem Implementations in C
│   │   ├── aes256.c             # AES-256 (ECB & CBC modes, Key Expansion)
│   │   ├── rsa.c                # RSA-2048 (Arbitrary-precision arithmetic, Keygen, Encrypt, Sign)
│   │   ├── ecc.c                # ECC secp256k1 (Point arithmetic, ECDH, ECDSA)
│   │   └── sha512.c             # SHA-512 (Streaming API, HMAC, Avalanche & Throughput tests)
│   └── python/                  # Quantum Cryptanalysis & Attack Simulations
│       ├── grover_attacks.py    # Grover's algorithm vs AES-128, SHA-512, RSA & ECC
│       └── shor_attacks.py      # Shor's algorithm (QFT period-finding) vs RSA & ECC
└── output/                      # Generated binaries, text outputs, and analysis plots
    ├── bin/                     # Compiled C binaries
    ├── grover_convergence.png   # Grover iteration probability convergence
    ├── security_reduction.png   # Post-quantum security bit reduction comparison
    ├── shor_qft_period.png      # Quantum Fourier Transform period-finding spectrum
    ├── shor_rsa_complexity.png  # Classical GNFS vs Quantum Shor complexity curve
    └── shor_ecdlp_complexity.png# Classical Pollard's rho vs Quantum Shor for ECC
```

---

## 🛠️ Prerequisites & Environment Setup

### 1. C Compiler
- **GCC** (MinGW-w64 on Windows, or GCC on Linux/macOS) supporting `C99` or later.
- Make tool (`mingw32-make` or `make`).

### 2. Python Environment
- **Python 3.8+** (tested on Python 3.14).
- Required packages:
  ```bash
  pip install numpy matplotlib
  ```

---

## 🚀 How to Build and Run

### Option A: Using the Makefile (Recommended)

1. **Build all C executables**:
   ```bash
   mingw32-make all     # On Windows (or 'make all' on Linux/macOS)
   ```
   *Binaries are created in `output/bin/`.*

2. **Execute all C implementations**:
   ```bash
   mingw32-make run     # Builds and executes AES-256, RSA, ECC, and SHA-512
   ```

3. **Execute Python Quantum Attack Simulations**:
   ```bash
   mingw32-make python  # Runs Grover's and Shor's attack simulations & generates plots
   ```

4. **Clean build artifacts**:
   ```bash
   mingw32-make clean
   ```

---

### Option B: Compiling and Running Individually

#### 1. AES-256 (C)
```bash
gcc -O2 -Wall -std=c99 -o output/bin/aes256 src/c/aes256.c
./output/bin/aes256
```
- Validates against NIST ECB Known Answer Test (KAT).
- Demonstrates CBC encryption, PKCS#7 padding, and decryption integrity.

#### 2. RSA (C)
```bash
gcc -O2 -Wall -std=c99 -o output/bin/rsa src/c/rsa.c
./output/bin/rsa
```
- Demonstrates RSA key generation, modular exponentiation, encryption, decryption, and digital signatures.

#### 3. ECC secp256k1 (C)
```bash
gcc -O2 -Wall -std=c99 -o output/bin/ecc src/c/ecc.c
./output/bin/ecc
```
- Implements 256-bit point addition, doubling, ECDH key agreement, and ECDSA signature verification.

#### 4. SHA-512 (C)
```bash
gcc -O2 -Wall -std=c99 -o output/bin/sha512 src/c/sha512.c
./output/bin/sha512
```
- Validates NIST FIPS 180-4 test vectors.
- Evaluates avalanche effect (>50% bit flip) and hashing throughput (MB/s).

#### 5. Grover's Algorithm Attack Simulation (Python)
```bash
py src/python/grover_attacks.py
```
- Simulates Grover diffusion and oracle operations on $N = 2^n$ state vectors.
- Analyzes quadratic speedup $O(\sqrt{N})$ on AES-128 and SHA-512 pre-images.
- Saves analysis plots to `output/grover_convergence.png` and `output/security_reduction.png`.

#### 6. Shor's Algorithm Attack Simulation (Python)
```bash
py src/python/shor_attacks.py
```
- Simulates Quantum Fourier Transform (QFT) and period finding $r$ for $a^r \equiv 1 \pmod N$.
- Analyzes polynomial-time factoring of RSA ($O(\log^3 N)$) and discrete logarithms on ECC.
- Saves analysis plots to `output/shor_qft_period.png`, `output/shor_rsa_complexity.png`, and `output/shor_ecdlp_complexity.png`.

---

## 📊 Summary of Cryptosystem Security & Quantum Resilience

| Algorithm | Classical Security | Quantum Attack | Post-Quantum Security | Status / Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| **AES-128** | 128 bits | Grover's ($O(2^{64})$) | 64 bits (effective) | **Vulnerable** → Upgrade to AES-256 |
| **AES-256** | 256 bits | Grover's ($O(2^{128})$) | 128 bits (effective) | **Secure** (meets 128-bit PQC threshold) |
| **SHA-512 (Pre-image)** | 512 bits | Grover's ($O(2^{256})$) | 256 bits | **Secure** (quantumly infeasible) |
| **SHA-512 (Collision)** | 256 bits | BHT algorithm ($O(2^{170})$)| 170 bits | **Secure** |
| **RSA-2048** | ~112 bits (GNFS) | Shor's ($O(\log^3 N)$) | **0 bits (Broken)** | **Migrate** to Lattice-based (CRYSTALS-Kyber) |
| **ECC (secp256k1)** | ~128 bits (Pollard's rho) | Shor's ($O(\log^3 n)$) | **0 bits (Broken)** | **Migrate** to Lattice-based (CRYSTALS-Dilithium) |

---

## 📚 References & Standards
1. **NIST FIPS PUB 197**: *Advanced Encryption Standard (AES)*
2. **RFC 8017**: *PKCS #1: RSA Cryptography Specifications Version 2.2*
3. **SEC 2**: *Recommended Elliptic Curve Domain Parameters (secp256k1)*
4. **NIST FIPS PUB 180-4**: *Secure Hash Standard (SHS)*
5. **Grover, L. K. (1996)**: *A fast quantum mechanical algorithm for database search*
6. **Shor, P. W. (1994)**: *Algorithms for quantum computation: discrete logarithms and factoring*
7. **NIST SP 800-208 / PQC Standards (2024)**: *FIPS 203 (ML-KEM), FIPS 204 (ML-DSA)*
