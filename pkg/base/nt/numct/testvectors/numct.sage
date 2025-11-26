#!/usr/bin/env sage

import json
import random
from math import isqrt

# Use a fixed seed for reproducibility
random.seed(0xdeadbeefcafebabe)

def rand_nat(bits):
    """Generate a random natural number with the given bit length."""
    if bits == 0:
        return 0
    return random.randint(0, (1 << bits) - 1)

def rand_int(bits):
    """Generate a random signed integer with magnitude up to bits."""
    n = rand_nat(bits)
    if random.choice([True, False]):
        return -n
    return n

def to_hex(n):
    """Convert an integer to hex string (without 0x prefix)."""
    if n == 0:
        return "0"
    if n < 0:
        return "-" + hex(abs(n))[2:]
    return hex(n)[2:]

def is_perfect_square(n):
    """Check if n is a perfect square."""
    if n < 0:
        return False
    root = isqrt(n)
    return root * root == n

vectors = {
    "nat_sqrt": [],
    "nat_and": [],
    "nat_or": [],
    "nat_xor": [],
    "int_sqrt": [],
    "int_and": [],
    "int_or": [],
    "int_xor": [],
}

# ============== Nat Sqrt ==============

# Fixed perfect squares (small - fast path)
nat_sqrt_perfect_small = [0, 1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 144, 256, 1000000]
for n in nat_sqrt_perfect_small:
    root = isqrt(n)
    vectors["nat_sqrt"].append({
        "n": to_hex(n),
        "root": to_hex(root),
        "ok": True,
    })

# Fixed non-perfect squares (small - fast path)
nat_sqrt_nonperfect_small = [2, 3, 5, 7, 8, 10, 15, 17, 99, 101]
for n in nat_sqrt_nonperfect_small:
    vectors["nat_sqrt"].append({
        "n": to_hex(n),
        "root": "0",
        "ok": False,
    })

# Large perfect squares (multi-limb path, > 64 bits)
large_roots = [
    1 << 64,      # 2^64
    1 << 100,     # 2^100
    1 << 128,     # 2^128
    1 << 200,     # 2^200
    (1 << 64) - 1,  # max uint64
    0x123456789ABCDEF0112233445566778899AABBCCDDEEFF,  # large arbitrary value
]
for root in large_roots:
    n = root * root
    vectors["nat_sqrt"].append({
        "n": to_hex(n),
        "root": to_hex(root),
        "ok": True,
    })

# Large non-perfect squares (multi-limb path)
large_nonperfect = [
    (1 << 65) + 1,
    (1 << 100) + 7,
    (1 << 128) - 1,
    (1 << 200) + 13,
]
for n in large_nonperfect:
    vectors["nat_sqrt"].append({
        "n": to_hex(n),
        "root": "0",
        "ok": False,
    })

# Random large perfect squares
for _ in range(8):
    bits = random.randint(65, 256)
    root = rand_nat(bits)
    n = root * root
    vectors["nat_sqrt"].append({
        "n": to_hex(n),
        "root": to_hex(root),
        "ok": True,
    })

# Random large non-perfect squares (n^2 + k where 0 < k < 2n)
for _ in range(8):
    bits = random.randint(65, 256)
    root = rand_nat(bits)
    if root == 0:
        root = 1
    k = random.randint(1, min(2 * root - 1, (1 << 32)))
    n = root * root + k
    vectors["nat_sqrt"].append({
        "n": to_hex(n),
        "root": "0",
        "ok": False,
    })

# ============== Nat And/Or/Xor ==============

# Fixed edge cases
nat_bitwise_fixed = [
    (0, 0),
    (0, 1),
    (1, 0),
    (1, 1),
    (0xFF, 0xFF),
    (0xFF, 0x00),
    (0xAA, 0x55),
    (0x12345678, 0x87654321),
    ((1 << 64) - 1, (1 << 64) - 1),  # max uint64
    ((1 << 64) - 1, 0),
    ((1 << 128) - 1, (1 << 64) - 1),  # different sizes
]

for a, b in nat_bitwise_fixed:
    vectors["nat_and"].append({
        "a": to_hex(a),
        "b": to_hex(b),
        "c": to_hex(a & b),
    })
    vectors["nat_or"].append({
        "a": to_hex(a),
        "b": to_hex(b),
        "c": to_hex(a | b),
    })
    vectors["nat_xor"].append({
        "a": to_hex(a),
        "b": to_hex(b),
        "c": to_hex(a ^ b),
    })

# Random cases with varying sizes (including multi-limb)
for _ in range(16):
    bits_a = random.randint(0, 256)
    bits_b = random.randint(0, 256)
    a = rand_nat(bits_a)
    b = rand_nat(bits_b)

    vectors["nat_and"].append({
        "a": to_hex(a),
        "b": to_hex(b),
        "c": to_hex(a & b),
    })
    vectors["nat_or"].append({
        "a": to_hex(a),
        "b": to_hex(b),
        "c": to_hex(a | b),
    })
    vectors["nat_xor"].append({
        "a": to_hex(a),
        "b": to_hex(b),
        "c": to_hex(a ^ b),
    })

# ============== Int Sqrt ==============

# Fixed perfect squares (small - fast path)
int_sqrt_perfect_small = [0, 1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 144, 256, 1000000]
for n in int_sqrt_perfect_small:
    root = isqrt(n)
    vectors["int_sqrt"].append({
        "n": to_hex(n),
        "root": to_hex(root),
        "ok": True,
    })

# Negative numbers (always fail)
int_sqrt_negative = [-1, -4, -9, -16, -100, -(1 << 64), -(1 << 128)]
for n in int_sqrt_negative:
    vectors["int_sqrt"].append({
        "n": to_hex(n),
        "root": "0",
        "ok": False,
    })

# Non-perfect squares (small - fast path)
int_sqrt_nonperfect_small = [2, 3, 5, 7, 8, 10, 15, 17, 99, 101]
for n in int_sqrt_nonperfect_small:
    vectors["int_sqrt"].append({
        "n": to_hex(n),
        "root": "0",
        "ok": False,
    })

# Large perfect squares (multi-limb path)
for root in large_roots:
    n = root * root
    vectors["int_sqrt"].append({
        "n": to_hex(n),
        "root": to_hex(root),
        "ok": True,
    })

# Large non-perfect squares
for n in large_nonperfect:
    vectors["int_sqrt"].append({
        "n": to_hex(n),
        "root": "0",
        "ok": False,
    })

# Random large perfect squares
for _ in range(8):
    bits = random.randint(65, 256)
    root = rand_nat(bits)
    n = root * root
    vectors["int_sqrt"].append({
        "n": to_hex(n),
        "root": to_hex(root),
        "ok": True,
    })

# ============== Int And/Or/Xor ==============
# Note: For signed integers, Python uses two's complement representation for bitwise ops

# Fixed edge cases (including negative numbers)
int_bitwise_fixed = [
    (0, 0),
    (0, 1),
    (1, 0),
    (1, 1),
    (-1, -1),
    (-1, 0),
    (-1, 1),
    (0x7FFFFFFFFFFFFFFF, -1),  # max int64 & -1
    (-0x8000000000000000, -1),  # min int64 & -1
    (0x7FFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF),
    (-0x8000000000000000, -0x8000000000000000),
    (0xFF, -0xFF),
    (-0xFF, 0xFF),
    (0xAA, -0x55),
    (-0xAA, 0x55),
    (1 << 128, -1),
    (-(1 << 128), 1),
    (-(1 << 128), -1),
]

for a, b in int_bitwise_fixed:
    vectors["int_and"].append({
        "a": to_hex(a),
        "b": to_hex(b),
        "c": to_hex(a & b),
    })
    vectors["int_or"].append({
        "a": to_hex(a),
        "b": to_hex(b),
        "c": to_hex(a | b),
    })
    vectors["int_xor"].append({
        "a": to_hex(a),
        "b": to_hex(b),
        "c": to_hex(a ^ b),
    })

# Random cases with varying sizes and signs (including multi-limb)
for _ in range(16):
    bits_a = random.randint(0, 256)
    bits_b = random.randint(0, 256)
    a = rand_int(bits_a)
    b = rand_int(bits_b)

    vectors["int_and"].append({
        "a": to_hex(a),
        "b": to_hex(b),
        "c": to_hex(a & b),
    })
    vectors["int_or"].append({
        "a": to_hex(a),
        "b": to_hex(b),
        "c": to_hex(a | b),
    })
    vectors["int_xor"].append({
        "a": to_hex(a),
        "b": to_hex(b),
        "c": to_hex(a ^ b),
    })

print(json.dumps(vectors, indent=2))
