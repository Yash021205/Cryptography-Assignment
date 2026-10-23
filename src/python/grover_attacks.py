"""
Grover's Algorithm – Quantum Attack Simulation
================================================
Grover's algorithm provides a quadratic speedup for unstructured search,
reducing brute-force key search from O(N) to O(√N).

This module SIMULATES Grover's oracle and diffusion operator classically,
and applies it conceptually to:
  1. AES-128 key search  (key space 2^128 → effective 2^64 with Grover)
  2. SHA-512 pre-image   (2^512 → 2^256 with Grover)
  3. ECC ECDLP           (not directly addressed by Grover, but partial speedup)

Classical simulation is limited to small toy parameters (actual quantum
hardware would need ~3,000 logical qubits for AES-128).

References:
  - Grover, L. K. (1996). "A fast quantum mechanical algorithm for database search."
  - Grassl, M. et al. (2016). "Applying Grover's algorithm to AES: quantum resource estimates."
  - NIST IR 8240 (2019). Post-Quantum Cryptography.

Author : CYG Assignment Group
Course : Cryptography
Date   : 2026
"""

import sys
import os

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import math
import time
import random
import hashlib
import struct
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ============================================================
# Section 1 – Grover's Algorithm Core (Classical Simulation)
# ============================================================

def grover_iterations_needed(n_bits: int) -> int:
    """Optimal number of Grover iterations: ⌊π/4 · √(2^n)⌋"""
    N = 2 ** n_bits
    return int(math.pi / 4 * math.sqrt(N))


def grover_simulate_small(n_bits: int, target: int) -> dict:
    """
    Classically simulate Grover's algorithm on n_bits qubits.
    Works for n_bits <= 20 (2^20 = 1M states; beyond that is memory-prohibitive).
    Returns timing and success info.
    """
    N = 2 ** n_bits
    assert target < N, "Target must be < 2^n_bits"

    # Initialize uniform superposition
    amplitudes = np.ones(N, dtype=complex) / math.sqrt(N)

    def oracle(amps: np.ndarray) -> np.ndarray:
        """Flip phase of the target state."""
        result = amps.copy()
        result[target] *= -1.0
        return result

    def diffusion(amps: np.ndarray) -> np.ndarray:
        """Grover diffusion (inversion about mean): 2|ψ⟩⟨ψ| - I"""
        mean = amps.mean()
        return 2 * mean - amps

    iterations = grover_iterations_needed(n_bits)
    probs_at_target = []

    start = time.perf_counter()
    for _ in range(iterations):
        amplitudes = oracle(amplitudes)
        amplitudes = diffusion(amplitudes)
        probs_at_target.append(abs(amplitudes[target]) ** 2)
    elapsed = time.perf_counter() - start

    probabilities = np.abs(amplitudes) ** 2
    measured = int(np.argmax(probabilities))

    return {
        "n_bits":        n_bits,
        "N":             N,
        "target":        target,
        "measured":      measured,
        "success":       measured == target,
        "iterations":    iterations,
        "prob_at_target": float(probs_at_target[-1]),
        "elapsed_sec":   elapsed,
        "probs_history": probs_at_target,
    }


# ============================================================
# Section 2 – Grover Attack on AES-128
# ============================================================

class GroverAES128Attack:
    """
    Theoretical Grover attack on AES-128.

    AES-128 key space: 2^128
    Classical brute-force: O(2^128) queries
    Grover speedup: O(2^64) queries     ← quadratic speedup

    We demonstrate with a tiny toy AES oracle (4-bit key space = 16 keys)
    to show the algorithm works, then extrapolate statistics to AES-128.
    """

    KEY_BITS_TOY = 8   # toy key space
    KEY_BITS_AES = 128  # real AES-128

    def toy_oracle(self, key: int, ciphertext: bytes, known_pt: bytes) -> bool:
        """
        Simulates an AES oracle for toy keys.
        In reality, the oracle would test if Encrypt(key, known_pt) == ciphertext.
        """
        # Simple toy cipher: key XOR plaintext
        ct = bytes(b ^ (key & 0xFF) for b in known_pt)
        return ct == ciphertext

    def run_toy_attack(self):
        """Run Grover's attack on toy AES (8-bit key)."""
        KEY_BITS = self.KEY_BITS_TOY
        N = 2 ** KEY_BITS

        # Choose a random target key
        true_key = random.randint(0, N - 1)
        known_pt = b"Hello!  "  # 8 bytes
        ciphertext = bytes(b ^ (true_key & 0xFF) for b in known_pt)

        print(f"  [Toy AES] Key space : 2^{KEY_BITS} = {N} keys")
        print(f"  [Toy AES] True key  : 0x{true_key:02x} = {true_key}")
        print(f"  [Toy AES] Known PT  : {known_pt}")
        print(f"  [Toy AES] Ciphertext: {ciphertext.hex()}")

        result = grover_simulate_small(KEY_BITS, true_key)

        # Verify oracle on measured key
        oracle_confirmed = self.toy_oracle(result["measured"], ciphertext, known_pt)

        print(f"\n  [Grover] Iterations    : {result['iterations']} (classical: {N})")
        print(f"  [Grover] Measured key  : 0x{result['measured']:02x} = {result['measured']}")
        print(f"  [Grover] Success       : {'✓' if result['success'] else '✗'}")
        print(f"  [Grover] Oracle verify : {'✓' if oracle_confirmed else '✗'}")
        print(f"  [Grover] P(target)     : {result['prob_at_target']:.6f}")
        print(f"  [Grover] Sim time      : {result['elapsed_sec']*1000:.3f} ms")

        return result

    def extrapolate_aes128(self):
        """Theoretical extrapolation to real AES-128."""
        N_classical = 2 ** self.KEY_BITS_AES
        N_grover    = 2 ** (self.KEY_BITS_AES // 2)
        ops_grover  = int(math.pi / 4 * math.sqrt(2 ** self.KEY_BITS_AES))

        print(f"\n  [AES-128 Extrapolation]")
        print(f"  Classical brute-force : 2^{self.KEY_BITS_AES} ≈ {2**self.KEY_BITS_AES:.2e} operations")
        print(f"  Grover's speedup      : O(√N) = 2^{self.KEY_BITS_AES//2} ≈ {ops_grover:.2e} oracle calls")
        print(f"  Qubit requirement     : ~{self._estimate_qubits_aes128()} logical qubits")
        print(f"  Security post-Grover  : 64 bits (equivalent classical)")
        print(f"  Mitigation            : Upgrade to AES-256 (128-bit post-quantum security)")

    @staticmethod
    def _estimate_qubits_aes128() -> str:
        """
        Grassl et al. (2016): ~2,953 logical qubits for AES-128 Grover search.
        """
        return "~2,953 logical qubits (Grassl et al., 2016)"


# ============================================================
# Section 3 – Grover Attack on SHA-512 Pre-image
# ============================================================

class GroverSHA512Attack:
    """
    Grover's attack on SHA-512 pre-image resistance.

    SHA-512 produces a 512-bit digest.
    Classical pre-image:  O(2^512)
    Grover pre-image:     O(2^256)  ← still computationally infeasible

    Collision resistance (birthday):  O(2^256) classical, O(2^170) quantum
    """

    BITS = 512

    def toy_demo(self, n_bits: int = 8):
        """Demo with n_bits truncated hash (toy oracle)."""
        N = 2 ** n_bits
        # The 'secret' preimage produces this truncated hash
        secret = random.randint(0, N - 1)
        target_hash = secret ^ 0b10110101  # simple toy hash

        def toy_hash_oracle(x):
            return (x ^ 0b10110101) == target_hash

        print(f"  [Toy SHA] Hash bits    : {n_bits}")
        print(f"  [Toy SHA] Target hash  : {target_hash:#0{n_bits//4+2}x}")

        result = grover_simulate_small(n_bits, secret)
        print(f"  [Grover] Iterations    : {result['iterations']}")
        print(f"  [Grover] Found preimage: 0x{result['measured']:02x}")
        print(f"  [Grover] Verified      : {'✓' if toy_hash_oracle(result['measured']) else '✗'}")
        print(f"  [Grover] P(target)     : {result['prob_at_target']:.6f}")
        return result

    def extrapolate_sha512(self):
        print(f"\n  [SHA-512 Extrapolation]")
        print(f"  Pre-image (classical) : 2^512 ≈ {2**512:.2e}")
        print(f"  Pre-image (Grover)    : 2^256 ≈ {2**256:.2e}  [still infeasible]")
        print(f"  Collision (classical) : 2^256 (birthday)")
        print(f"  Collision (quantum)   : 2^170 (Brassard-Hoyer-Tapp)")
        print(f"  Post-quantum secure?  : YES  (256-bit security with 512-bit digest)")
        print(f"  NIST PQC guidance     : SHA-512/256 recommended for PQC contexts")


# ============================================================
# Section 4 – Grover Attack on ECC (ECDLP context)
# ============================================================

class GroverECCAttack:
    """
    Grover's algorithm has limited direct applicability to ECDLP.
    The key attack on ECC comes from Shor's algorithm (see shor_attacks.py).
    Grover provides a partial speedup for a specific sub-routine in some
    quantum ECDLP algorithms.

    Classical ECDLP (Pollard's rho): O(√n) ≈ O(2^128) for secp256k1
    Quantum (Shor-based):             O(log^3 n) – see shor_attacks.py
    """

    def analyze(self, curve_bits: int = 256):
        security = curve_bits // 2
        print(f"  Curve bits             : {curve_bits}")
        print(f"  Classical ECDLP        : O(2^{security}) ≈ Pollard's rho")
        print(f"  Grover speedup on ECDLP: Limited – primary threat is Shor's")
        print(f"  Quantum ECDLP (Shor)   : O(log³n) – see shor_attacks.py")
        print(f"  Qubit estimate         : ~2,330 logical qubits (secp256k1)")


# ============================================================
# Section 5 – Visualization
# ============================================================

def plot_grover_convergence(results: list, save_path: str):
    """Plot probability of finding target vs iteration for different key sizes."""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))
    fig.suptitle("Grover's Algorithm – Quantum Attack Simulation",
                 fontsize=15, fontweight='bold', color='#1a1a2e')

    # Left: Probability convergence for each key size
    ax1 = axes[0]
    cmap = matplotlib.colormaps['plasma']
    colors = cmap(np.linspace(0.1, 0.9, len(results)))
    for res, color in zip(results, colors):
        ax1.plot(res["probs_history"], color=color,
                 label=f"n={res['n_bits']} bits (N=2^{res['n_bits']})", linewidth=2)
    ax1.set_xlabel("Grover Iteration", fontsize=12)
    ax1.set_ylabel("P(target state)", fontsize=12)
    ax1.set_title("Probability Amplification", fontsize=13)
    ax1.legend(fontsize=9)
    ax1.grid(True, alpha=0.3)
    ax1.set_ylim([0, 1.1])
    ax1.axhline(y=1.0, color='green', linestyle='--', alpha=0.5, label='P=1')

    # Right: Classical vs Quantum query complexity
    ax2 = axes[1]
    bits = np.arange(4, 256, 4)
    classical = 2.0 ** bits
    quantum   = np.pi / 4 * np.sqrt(2.0 ** bits)

    ax2.semilogy(bits, classical, 'b-', linewidth=2, label='Classical O(N)')
    ax2.semilogy(bits, quantum,   'r-', linewidth=2, label="Grover's O(√N)")

    # Mark specific points
    for key_size, color, label in [(128, 'orange', 'AES-128'), (256, 'purple', 'AES-256')]:
        c_ops = 2.0 ** key_size
        q_ops = math.pi / 4 * math.sqrt(2.0 ** key_size)
        ax2.scatter([key_size], [c_ops], color=color, zorder=5, s=80)
        ax2.scatter([key_size], [q_ops], color=color, zorder=5, s=80, marker='*')
        ax2.annotate(label, xy=(key_size, q_ops),
                     xytext=(key_size + 5, q_ops * 100),
                     fontsize=9, color=color,
                     arrowprops=dict(arrowstyle='->', color=color, lw=1))

    ax2.set_xlabel("Key/Hash Size (bits)", fontsize=12)
    ax2.set_ylabel("Query Complexity (log scale)", fontsize=12)
    ax2.set_title("Classical vs Quantum Search Complexity", fontsize=13)
    ax2.legend(fontsize=10)
    ax2.grid(True, alpha=0.3, which='both')

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"\n  [Plot] Saved → {save_path}")


def plot_security_reduction(save_path: str):
    """Bar chart showing classical vs post-Grover security levels."""
    labels   = ['AES-128', 'AES-256', 'RSA-2048', 'ECC-256\n(secp256k1)', 'SHA-512\n(pre-image)', 'SHA-512\n(collision)']
    classic  = [128, 256, 112, 128, 512, 256]
    grover   = [ 64, 128,  56,  64, 256, 170]

    x = np.arange(len(labels))
    width = 0.35

    fig, ax = plt.subplots(figsize=(12, 6))
    bars1 = ax.bar(x - width/2, classic, width, label='Classical Security (bits)',
                   color='#2196F3', alpha=0.85, edgecolor='white')
    bars2 = ax.bar(x + width/2, grover,  width, label="Post-Grover Security (bits)",
                   color='#F44336', alpha=0.85, edgecolor='white')

    ax.axhline(y=128, color='green', linestyle='--', linewidth=1.5,
               label='128-bit security threshold')
    ax.axhline(y=64,  color='orange', linestyle=':', linewidth=1.5,
               label='64-bit security (vulnerable)')

    ax.set_xlabel("Cryptographic Scheme", fontsize=12)
    ax.set_ylabel("Security Level (bits)", fontsize=12)
    ax.set_title("Security Level Reduction Due to Grover's Algorithm",
                 fontsize=13, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3, axis='y')

    for bar in bars1:
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                f'{int(bar.get_height())}', ha='center', fontsize=9, color='#2196F3')
    for bar in bars2:
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                f'{int(bar.get_height())}', ha='center', fontsize=9, color='#F44336')

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  [Plot] Saved → {save_path}")


# ============================================================
# Section 6 – Statistics & Summary Table
# ============================================================

def print_summary_table():
    print("\n" + "="*70)
    print("  Grover's Algorithm – Security Impact Summary Table")
    print("="*70)
    header = f"{'Scheme':<18} {'Classical':>12} {'Grover':>12} {'Qubits':>16} {'Status':<12}"
    print(header)
    print("-" * 70)
    rows = [
        ("AES-128",     "2^128", "2^64",  "~2,953",  "VULNERABLE ✗"),
        ("AES-256",     "2^256", "2^128", "~6,681",  "SECURE ✓"),
        ("SHA-512/PI",  "2^512", "2^256", "~261,000","SECURE ✓"),
        ("SHA-512/COL", "2^256", "2^170", "~261,000","SECURE ✓"),
        ("ECC-256",     "2^128", "N/A",   "N/A",     "Use Shor's"),
        ("RSA-2048",    "2^112", "N/A",   "N/A",     "Use Shor's"),
    ]
    for scheme, cls, grv, qb, status in rows:
        print(f"  {scheme:<16} {cls:>12} {grv:>12} {qb:>16} {status:<12}")
    print("="*70)
    print("  Legend: PI = Pre-image, COL = Collision, N/A = Shor's is primary threat")


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    print("=" * 70)
    print("    GROVER'S ALGORITHM – Quantum Attack Simulation (Python)")
    print("=" * 70)

    # --- 1. Core Grover simulation at multiple sizes ---
    print("\n[1] Core Grover Simulation (small key spaces)\n")
    sim_results = []
    for nb in [4, 6, 8, 10]:
        target = random.randint(0, 2**nb - 1)
        print(f"  n={nb} bits (N={2**nb}), target={target}")
        res = grover_simulate_small(nb, target)
        sim_results.append(res)
        print(f"  Measured={res['measured']}, P={res['prob_at_target']:.4f}, "
              f"iters={res['iterations']}, "
              f"{'✓' if res['success'] else '✗'}\n")

    # --- 2. AES-128 Grover Attack ---
    print("[2] Grover Attack on AES-128\n")
    aes_attack = GroverAES128Attack()
    aes_result  = aes_attack.run_toy_attack()
    aes_attack.extrapolate_aes128()

    # --- 3. SHA-512 Grover Attack ---
    print("\n[3] Grover Attack on SHA-512 Pre-image\n")
    sha_attack = GroverSHA512Attack()
    sha_result  = sha_attack.toy_demo(n_bits=8)
    sha_attack.extrapolate_sha512()

    # --- 4. ECC ---
    print("\n[4] Grover vs ECC (secp256k1)\n")
    ecc = GroverECCAttack()
    ecc.analyze(256)

    # --- 5. Summary Table ---
    print_summary_table()

    # --- 6. Plots ---
    print("\n[5] Generating Plots...\n")
    plot_grover_convergence(sim_results, os.path.join(OUTPUT_DIR, "grover_convergence.png"))
    plot_security_reduction(os.path.join(OUTPUT_DIR, "security_reduction.png"))

    print("\n" + "=" * 70)
    print("    Grover's Simulation Complete.")
    print("=" * 70)
