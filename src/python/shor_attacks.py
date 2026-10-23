"""
Shor's Algorithm – Quantum Attack Simulation
=============================================
Shor's algorithm breaks public-key cryptography (RSA, ECC) in polynomial
time by reducing factoring / discrete logarithm to quantum period-finding
via the Quantum Fourier Transform (QFT).

This module SIMULATES Shor's algorithm classically for small numbers and
provides rigorous theoretical analysis for:
  1. RSA-2048   – Integer Factorization Problem (IFP)
  2. ECC-256    – Elliptic Curve Discrete Logarithm Problem (ECDLP)
  3. AES-128    – Not directly attacked by Shor's (Grover's applies)
  4. SHA-512    – Not directly attacked by Shor's (Grover's applies)

References:
  - Shor, P. W. (1994). "Algorithms for quantum computation."
  - Preskill, J. (2018). "Quantum Computing in the NISQ era and beyond."
  - Banegas, G. et al. (2021). "Concrete quantum cryptanalysis of binary elliptic curves."
  - NIST SP 800-186 (2022). Recommendations for Discrete Logarithm-Based Cryptography.

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
import fractions
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from typing import Optional, Tuple, List

# ============================================================
# Section 1 – Quantum Fourier Transform (Classical Simulation)
# ============================================================

def qft_matrix(n: int) -> np.ndarray:
    """Construct the n×n QFT matrix (classical simulation)."""
    omega = np.exp(2j * np.pi / n)
    indices = np.arange(n)
    return (1.0 / math.sqrt(n)) * (omega ** np.outer(indices, indices))


def apply_qft(state: np.ndarray) -> np.ndarray:
    """Apply QFT to a quantum state vector (size must be power of 2)."""
    n = len(state)
    QFT = qft_matrix(n)
    return QFT @ state


def apply_iqft(state: np.ndarray) -> np.ndarray:
    """Apply inverse QFT."""
    n = len(state)
    QFT = qft_matrix(n)
    return QFT.conj().T @ state


# ============================================================
# Section 2 – Period Finding (Heart of Shor's Algorithm)
# ============================================================

def modular_exponentiation(a: int, x: int, N: int) -> int:
    """Compute a^x mod N using fast binary exponentiation."""
    return pow(a, x, N)


def quantum_period_finding_simulate(a: int, N: int,
                                     precision_bits: int = 8) -> Optional[int]:
    """
    Classical simulation of the quantum period-finding subroutine.

    The quantum register is of size Q = 2^precision_bits.
    We create a superposition, apply the modular exponentiation oracle,
    measure the second register, then apply QFT to find the period.

    Returns the period r such that a^r ≡ 1 (mod N), or None on failure.
    """
    Q = 2 ** precision_bits  # number of computational basis states

    # Step 1: Initialize uniform superposition |ψ⟩ = Σ |x⟩ / √Q
    state = np.ones(Q, dtype=complex) / math.sqrt(Q)

    # Step 2: Apply oracle U_f: |x⟩ → a^x mod N
    #         After measuring the second register (f(x0)), only states
    #         x0, x0+r, x0+2r, ... survive → periodic state
    x0 = random.randint(0, Q - 1)
    f_x0 = modular_exponentiation(a, x0, N)

    # Collapse to periodic superposition
    periodic_state = np.zeros(Q, dtype=complex)
    for x in range(Q):
        if modular_exponentiation(a, x, N) == f_x0:
            periodic_state[x] = 1.0

    norm = np.linalg.norm(periodic_state)
    if norm < 1e-10:
        return None
    periodic_state /= norm

    # Step 3: Apply QFT to the first register
    qft_state = apply_qft(periodic_state)

    # Step 4: Measure – sample from |QFT|^2 probability distribution
    probs = np.abs(qft_state) ** 2
    measured = np.random.choice(Q, p=probs / probs.sum())

    # Step 5: Classical post-processing with continued fractions
    if measured == 0:
        return None

    # Best rational approximation: measured/Q ≈ j/r for some j
    frac = fractions.Fraction(measured, Q).limit_denominator(N)
    r_candidate = frac.denominator

    # Verify
    if r_candidate > 0 and modular_exponentiation(a, r_candidate, N) == 1:
        return r_candidate

    # Try 2r, 3r (may be multiples)
    for mult in [2, 3]:
        r2 = r_candidate * mult
        if r2 < N and modular_exponentiation(a, r2, N) == 1:
            return r2

    return None


# ============================================================
# Section 3 – Shor's Factoring Algorithm
# ============================================================

class ShorFactoring:
    """
    Shor's algorithm for integer factorization.

    Classically simulates the quantum period-finding step.
    Works correctly for small semiprimes (N < 1000 for speed).
    """

    def __init__(self, verbose: bool = True):
        self.verbose = verbose

    def classical_order_finding(self, a: int, N: int) -> Optional[int]:
        """Classical (brute-force) order finding – used to verify quantum result."""
        if math.gcd(a, N) != 1:
            return None
        for r in range(1, N + 1):
            if pow(a, r, N) == 1:
                return r
        return None

    def factor(self, N: int, max_attempts: int = 50) -> Optional[Tuple[int, int]]:
        """
        Factor N using Shor's algorithm.
        Returns (p, q) such that p * q = N, or None on failure.
        """
        if N < 2:
            return None
        if N % 2 == 0:
            return (2, N // 2)
        if self._is_prime(N):
            return None  # N is prime, cannot factor

        start = time.perf_counter()

        for attempt in range(1, max_attempts + 1):
            # Step 1: Pick random a in [2, N-1]
            a = random.randint(2, N - 1)
            g = math.gcd(a, N)
            if g > 1:
                if self.verbose:
                    print(f"    [Attempt {attempt}] Lucky GCD! a={a}, gcd={g}")
                return (g, N // g)

            # Step 2: Quantum period finding (simulated classically)
            # Choose precision bits based on N size
            precision = max(8, int(math.ceil(math.log2(N))) + 2)
            precision = min(precision, 12)  # cap for speed

            r = quantum_period_finding_simulate(a, N, precision_bits=precision)

            # Fallback to classical order finding for small N
            if r is None:
                r = self.classical_order_finding(a, N)

            if r is None or r % 2 != 0:
                if self.verbose and attempt <= 5:
                    print(f"    [Attempt {attempt}] a={a}, r={r} (odd/None, retry)")
                continue

            # Step 3: Compute candidates a^(r/2) ± 1
            half_r = r // 2
            x = pow(a, half_r, N)

            if x == N - 1:   # a^(r/2) ≡ -1 (mod N), fail
                continue

            p = math.gcd(x + 1, N)
            q = math.gcd(x - 1, N)

            for candidate in [p, q]:
                if 1 < candidate < N and N % candidate == 0:
                    elapsed = time.perf_counter() - start
                    if self.verbose:
                        print(f"    [Attempt {attempt}] a={a}, r={r}, "
                              f"x=a^(r/2) mod N = {x}")
                        print(f"    Found factors: {candidate} × {N // candidate} = {N}")
                        print(f"    Time: {elapsed*1000:.3f} ms")
                    return (candidate, N // candidate)

        return None

    @staticmethod
    def _is_prime(n: int) -> bool:
        if n < 2: return False
        if n == 2: return True
        if n % 2 == 0: return False
        for i in range(3, int(math.sqrt(n)) + 1, 2):
            if n % i == 0: return False
        return True

    def demo_rsa_factoring(self):
        """Demonstrate factoring small RSA-like semiprimes."""
        print("  [Shor's] Factoring demonstration (small primes):")
        test_cases = [
            (15, "3×5"),   (21, "3×7"), (35, "5×7"),
            (77, "7×11"), (91, "7×13"), (143, "11×13"),
            (221, "13×17"), (323, "17×19"),
        ]
        results = []
        for N, expected in test_cases:
            start = time.perf_counter()
            result = self.factor(N, max_attempts=100)
            elapsed = (time.perf_counter() - start) * 1000
            if result:
                p, q = sorted(result)
                success = N == p * q
                print(f"    N={N:>5} ({expected:<6}) → {p}×{q}  "
                      f"{'✓' if success else '✗'}  [{elapsed:.2f}ms]")
                results.append((N, p, q, success, elapsed))
            else:
                print(f"    N={N:>5} → FAILED to factor")
        return results

    def rsa2048_analysis(self):
        """Theoretical analysis of Shor's attack on RSA-2048."""
        bits = 2048
        print(f"\n  [RSA-{bits} Analysis]")
        print(f"  Modulus size            : {bits} bits")
        print(f"  Classical best (GNFS)   : O(exp(1.9 * (log N)^(1/3) * (log log N)^(2/3)))")
        print(f"  Classical ops estimate  : ~2^112 ops (considered secure)")
        print(f"  Shor's quantum attack   : O((log N)^2 * log log N * log log log N)")
        print(f"  Quantum gate count      : ~3.97×10^10 Toffoli gates (Roetteler 2017)")
        print(f"  Logical qubit estimate  : ~4,098 logical qubits")
        print(f"  Post-quantum status     : BROKEN by Shor's algorithm")
        print(f"  Migration target        : CRYSTALS-Kyber (NIST PQC Round 3 winner)")


# ============================================================
# Section 4 – Shor's Attack on ECC (ECDLP)
# ============================================================

class ShorECDLP:
    """
    Shor's algorithm for the Elliptic Curve Discrete Logarithm Problem (ECDLP).

    Given P and Q = k*P on an elliptic curve, find k.
    Quantum reduction: ECDLP → Abelian Hidden Subgroup Problem (HSP)
    solved by QFT in polynomial time.

    Ekerå-Håstad (2017) quantum algorithm for ECDLP:
      - Requires ~2,330 logical qubits for secp256k1.
      - Poly-time: O(log³ n) quantum gates.
    """

    def classical_ecdlp_toy(self, G: int, Q: int, p: int) -> Optional[int]:
        """Baby-step Giant-step ECDLP on toy elliptic curve (over Fp, additive group)."""
        n = p
        m = int(math.ceil(math.sqrt(n)))

        # Baby steps: compute j*G for j = 0 to m-1
        baby = {}
        for j in range(m):
            baby[(G * j) % p] = j

        # Giant steps: check Q - i*m*G
        factor = pow(G, m, p) if G != 0 else 0
        current = Q
        for i in range(m + 1):
            if current in baby:
                k = (i * m + baby[current]) % n
                return k
            current = (current - factor) % p
        return None

    def demo_ecdlp(self):
        """Demonstrate classical ECDLP solution (toy group)."""
        print("  [ECDLP] Toy discrete log demonstration (mod p arithmetic):")
        cases = [(5, 17, 23), (3, 51, 61), (7, 23, 47)]
        for G, Q, p in cases:
            start = time.perf_counter()
            k = self.classical_ecdlp_toy(G, Q, p)
            elapsed = (time.perf_counter() - start) * 1000
            if k is not None:
                verify = (G * k) % p == Q
                print(f"    k*G≡Q (mod {p}): G={G}, Q={Q} → k={k}  "
                      f"verify: {'✓' if verify else '✗'}  [{elapsed:.3f}ms]")

    def secp256k1_analysis(self):
        """Theoretical analysis of Shor's attack on secp256k1."""
        bits = 256
        print(f"\n  [ECC secp256k1 Analysis]")
        print(f"  Curve field size        : {bits} bits")
        print(f"  Group order             : ~2^{bits}")
        print(f"  Classical ECDLP         : O(√n) ≈ O(2^128)  [Pollard's rho]")
        print(f"  Shor's quantum attack   : O(log³ n) = O({bits}³) ≈ {bits**3:,} gates")
        print(f"  Logical qubit estimate  : ~2,330 logical qubits (Roetteler 2017)")
        print(f"  Post-quantum status     : BROKEN by Shor's algorithm")
        print(f"  Migration target        : CRYSTALS-Dilithium (NIST PQC signatures)")

    def plot_ecdlp_complexity(self, save_path: str):
        bits_range = np.arange(64, 512, 8)
        classical = 2 ** (bits_range / 2)        # Pollard's rho
        quantum   = bits_range ** 3               # Shor's ECDLP

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.semilogy(bits_range, classical, 'b-', lw=2, label="Classical Pollard's rho: O(√n) ≈ O(2^{n/2})")
        ax.semilogy(bits_range, quantum,   'r-', lw=2, label="Shor's Quantum: O(log³n)")

        for bits, label in [(256, "secp256k1"), (384, "P-384"), (521, "P-521")]:
            if bits in bits_range:
                idx = np.where(bits_range == bits)[0][0]
                ax.scatter([bits], [classical[idx]], color='blue', zorder=5, s=80)
                ax.scatter([bits], [quantum[idx]],   color='red',  zorder=5, s=80, marker='*')
                ax.annotate(label, xy=(bits, quantum[idx]),
                            xytext=(bits+10, quantum[idx]*10),
                            fontsize=9, arrowprops=dict(arrowstyle='->', lw=1))

        ax.set_xlabel("ECC Key Size (bits)", fontsize=12)
        ax.set_ylabel("Operation Count (log scale)", fontsize=12)
        ax.set_title("Classical vs Quantum Attack on ECDLP\n(Shor's Algorithm)",
                     fontsize=13, fontweight='bold')
        ax.legend(fontsize=10)
        ax.grid(True, alpha=0.3, which='both')
        plt.tight_layout()
        plt.savefig(save_path, dpi=150, bbox_inches='tight')
        plt.close()
        print(f"  [Plot] Saved → {save_path}")


# ============================================================
# Section 5 – Shor's vs AES and SHA-512 (Context)
# ============================================================

def shor_vs_symmetric():
    """
    Shor's algorithm CANNOT directly attack symmetric ciphers (AES)
    or hash functions (SHA-512) as they do not rely on number-theoretic
    hard problems (factoring / discrete log).

    The quantum threat to AES-128 and SHA-512 comes from GROVER'S algorithm.
    """
    print("\n  [Shor's vs Symmetric Crypto]")
    print("  AES-128 / AES-256  : NOT directly broken by Shor's algorithm")
    print("                       → Grover's provides 2× bit-security reduction")
    print("  SHA-512            : NOT directly broken by Shor's algorithm")
    print("                       → Grover's pre-image: 2^256 (still infeasible)")
    print("  Conclusion         : Shor's primary targets are RSA and ECC")
    print("                       Symmetric/hash algorithms need doubled key sizes")


# ============================================================
# Section 6 – QFT Visualization
# ============================================================

def plot_qft_period(a: int, N: int, save_path: str, precision: int = 6):
    """Plot the QFT output showing peaks at multiples of Q/r."""
    Q = 2 ** precision
    r = None
    for r_test in range(1, N + 1):
        if pow(a, r_test, N) == 1:
            r = r_test
            break

    # Build periodic state
    x0 = 0
    f_x0 = pow(a, x0, N)
    periodic = np.zeros(Q, dtype=complex)
    for x in range(Q):
        if pow(a, x, N) == f_x0:
            periodic[x] = 1.0
    norm = np.linalg.norm(periodic)
    if norm > 1e-10:
        periodic /= norm

    qft_out = apply_qft(periodic)
    probs = np.abs(qft_out) ** 2

    fig, axes = plt.subplots(2, 1, figsize=(12, 8))
    fig.suptitle(f"Shor's Algorithm – QFT Period Finding\n(a={a}, N={N}, r={r})",
                 fontsize=14, fontweight='bold')

    x_axis = np.arange(Q)

    axes[0].bar(x_axis, np.abs(periodic) ** 2, color='#2196F3', alpha=0.7)
    axes[0].set_title(f"Input Register: Periodic State (period r={r})", fontsize=11)
    axes[0].set_xlabel("x"); axes[0].set_ylabel("|ψ(x)|²")
    axes[0].grid(True, alpha=0.3)

    axes[1].bar(x_axis, probs, color='#F44336', alpha=0.7)
    if r and r > 0:
        for k in range(Q // r + 1):
            peak = k * Q // r
            if peak < Q:
                axes[1].axvline(x=peak, color='green', linestyle='--', alpha=0.7, linewidth=1.5)
    axes[1].set_title(f"After QFT: Peaks at multiples of Q/r = {Q}/{r if r else '?'}", fontsize=11)
    axes[1].set_xlabel("Frequency bin k"); axes[1].set_ylabel("Probability")
    axes[1].grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  [Plot] Saved → {save_path}")


def plot_shor_rsa_complexity(save_path: str):
    """Plot classical GNFS vs Shor's attack complexity for RSA."""
    bits = np.arange(512, 8192, 64)

    # Classical GNFS: exp(1.9 * n^(1/3) * (log n)^(2/3)) where n = log2(N) * log(2)
    log_N = bits * math.log(2)
    gnfs  = np.exp(1.9 * (log_N ** (1/3)) * (np.log(log_N) ** (2/3)))

    # Shor's: O((log N)^3) – polynomial
    shor_gates = (bits * math.log(2)) ** 3

    fig, ax = plt.subplots(figsize=(12, 6))
    ax.semilogy(bits, gnfs,       'b-', lw=2, label="Classical GNFS: O(exp(n^{1/3} log^{2/3}))")
    ax.semilogy(bits, shor_gates, 'r-', lw=2, label="Shor's Algorithm: O(log³N) [polynomial]")

    for rsa_bits, color in [(1024,'orange'), (2048,'purple'), (4096,'green')]:
        idx = np.argmin(np.abs(bits - rsa_bits))
        ax.scatter([rsa_bits], [gnfs[idx]],       color=color, s=100, zorder=5)
        ax.scatter([rsa_bits], [shor_gates[idx]], color=color, s=100, zorder=5, marker='*')
        ax.annotate(f"RSA-{rsa_bits}", xy=(rsa_bits, gnfs[idx]),
                    xytext=(rsa_bits+100, gnfs[idx]*1e5),
                    fontsize=9, color=color,
                    arrowprops=dict(arrowstyle='->', color=color))

    ax.set_xlabel("RSA Key Size (bits)", fontsize=12)
    ax.set_ylabel("Computational Complexity (log scale)", fontsize=12)
    ax.set_title("RSA Classical vs Quantum Attack Complexity\n(Shor's Algorithm)",
                 fontsize=13, fontweight='bold')
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3, which='both')
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  [Plot] Saved → {save_path}")


def print_summary_table():
    """Print comprehensive Shor's attack summary table."""
    print("\n" + "=" * 75)
    print("  Shor's Algorithm – Security Impact Summary")
    print("=" * 75)
    header = f"{'Scheme':<18} {'Classical Complexity':<26} {'Shor Complexity':<18} {'Status'}"
    print(header)
    print("-" * 75)
    rows = [
        ("RSA-2048",    "O(exp(n^(1/3)·logn^(2/3)))", "O(log³n)",  "BROKEN ✗"),
        ("RSA-4096",    "O(exp(n^(1/3)·logn^(2/3)))", "O(log³n)",  "BROKEN ✗"),
        ("ECC-256",     "O(√n) = O(2^128)",            "O(log³n)",  "BROKEN ✗"),
        ("ECC-384",     "O(√n) = O(2^192)",            "O(log³n)",  "BROKEN ✗"),
        ("AES-128",     "O(2^128)",                    "Not appl.", "Use Grover"),
        ("AES-256",     "O(2^256)",                    "Not appl.", "Use Grover"),
        ("SHA-512",     "O(2^512)",                    "Not appl.", "Use Grover"),
    ]
    for scheme, cls, shor, status in rows:
        print(f"  {scheme:<18} {cls:<26} {shor:<18} {status}")
    print("=" * 75)
    print("  Note: Shor's targets asymmetric crypto; Grover's targets symmetric/hash")


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    print("=" * 70)
    print("    SHOR'S ALGORITHM – Quantum Attack Simulation (Python)")
    print("=" * 70)

    os.makedirs("output", exist_ok=True)

    # --- 1. Integer Factoring (Shor's) ---
    print("\n[1] Shor's Algorithm – Integer Factorization\n")
    shor = ShorFactoring(verbose=True)
    factor_results = shor.demo_rsa_factoring()
    shor.rsa2048_analysis()

    # --- 2. ECC ECDLP ---
    print("\n[2] Shor's Algorithm – ECDLP on ECC\n")
    ecc = ShorECDLP()
    ecc.demo_ecdlp()
    ecc.secp256k1_analysis()

    # --- 3. Context: AES and SHA-512 ---
    print("\n[3] Shor's vs Symmetric Cryptography\n")
    shor_vs_symmetric()

    # --- 4. Summary ---
    print_summary_table()

    # --- 5. Plots ---
    print("\n[4] Generating Plots...\n")

    # QFT visualization
    plot_qft_period(a=7, N=15, save_path="output/shor_qft_period.png")

    # RSA complexity comparison
    plot_shor_rsa_complexity("output/shor_rsa_complexity.png")

    # ECC ECDLP complexity
    ecc.plot_ecdlp_complexity("output/shor_ecdlp_complexity.png")

    # --- 6. Additional: Period finding verification ---
    print("\n[5] Period Finding Verification\n")
    test_cases = [(2, 15), (7, 15), (3, 35), (5, 21), (4, 21)]
    print(f"  {'a':>4} {'N':>5}  {'r (quantum)':>14} {'r (classical)':>15} {'match':>6}")
    print(f"  {'-'*4} {'-'*5}  {'-'*14} {'-'*15} {'-'*6}")
    for a, N in test_cases:
        r_q = quantum_period_finding_simulate(a, N, precision_bits=8)
        r_c = None
        for r_test in range(1, N + 1):
            if pow(a, r_test, N) == 1:
                r_c = r_test
                break
        match = "✓" if (r_q is not None and r_q > 0 and pow(a, r_q, N) == 1) else "—"
        print(f"  {a:>4} {N:>5}  {str(r_q):>14} {str(r_c):>15} {match:>6}")

    print("\n" + "=" * 70)
    print("    Shor's Simulation Complete.")
    print("=" * 70)
