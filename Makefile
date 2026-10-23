# Makefile for CYG Cryptography Assignment
# ==========================================
# Builds all C implementations and runs all programs.
#
# Requirements:
#   - GCC (MinGW on Windows, or native GCC on Linux/macOS)
#   - Python 3.8+ with numpy, matplotlib
#
# Usage:
#   make all        - Build all C programs
#   make run        - Build and run all programs
#   make python     - Run Python quantum attack simulations
#   make clean      - Remove compiled binaries

CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -std=c99 -lm
PYTHON  ?= py
SRCDIR  = src/c
OUTDIR  = output/bin

# C targets
AES256  = $(OUTDIR)/aes256
RSA     = $(OUTDIR)/rsa
ECC     = $(OUTDIR)/ecc
SHA512  = $(OUTDIR)/sha512

.PHONY: all run python clean dirs

all: dirs $(AES256) $(RSA) $(ECC) $(SHA512)

dirs:
	mkdir -p $(OUTDIR)
	mkdir -p output

$(AES256): $(SRCDIR)/aes256.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[BUILD] aes256 ✓"

$(RSA): $(SRCDIR)/rsa.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[BUILD] rsa ✓"

$(ECC): $(SRCDIR)/ecc.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[BUILD] ecc ✓"

$(SHA512): $(SRCDIR)/sha512.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "[BUILD] sha512 ✓"

run: all
	@echo ""
	@echo "=============================="
	@echo " Running AES-256"
	@echo "=============================="
	$(AES256)
	@echo ""
	@echo "=============================="
	@echo " Running RSA"
	@echo "=============================="
	$(RSA)
	@echo ""
	@echo "=============================="
	@echo " Running ECC"
	@echo "=============================="
	$(ECC)
	@echo ""
	@echo "=============================="
	@echo " Running SHA-512"
	@echo "=============================="
	$(SHA512)

python:
	@echo ""
	@echo "=============================="
	@echo " Running Grover's Attack"
	@echo "=============================="
	cd src/python && $(PYTHON) grover_attacks.py
	@echo ""
	@echo "=============================="
	@echo " Running Shor's Attack"
	@echo "=============================="
	cd src/python && $(PYTHON) shor_attacks.py

clean:
	rm -rf $(OUTDIR)
	@echo "[CLEAN] Done."
