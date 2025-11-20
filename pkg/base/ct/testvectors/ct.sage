import json
import random


def rand_bytes(n):
    return bytes(random.getrandbits(8) for _ in range(n))


def to_hex(b):
    return b.hex()


vector = {
    "and": [],
    "or": [],
    "not": [],
}

# Use a fixed seed for reproducibility
random.seed(b"cafebabe")

# Some fixed edge/interesting patterns
fixed_pairs = [
    (b"", b""),
    (b"\x00", b"\x00"),
    (b"\xff", b"\xff"),
    (b"\x0f", b"\xf0"),
    (b"\xaa\x55", b"\x55\xaa"),
]

for x, y in fixed_pairs:
    n = min(len(x), len(y))

    z_and = bytes((x[i] & y[i]) for i in range(n))
    z_or = bytes((x[i] | y[i]) for i in range(n))

    vector["and"].append({
        "x": to_hex(x),
        "y": to_hex(y),
        "z": to_hex(z_and),
    })

    vector["or"].append({
        "x": to_hex(x),
        "y": to_hex(y),
        "z": to_hex(z_or),
    })

# Random-length cases to exercise the min(len(x), len(y)) behavior
for _ in range(16):
    len_x = random.randint(0, 64)
    len_y = random.randint(0, 64)

    x = rand_bytes(len_x)
    y = rand_bytes(len_y)

    n = min(len_x, len_y)

    z_and = bytes((x[i] & y[i]) for i in range(n))
    z_or = bytes((x[i] | y[i]) for i in range(n))

    vector["and"].append({
        "x": to_hex(x),
        "y": to_hex(y),
        "z": to_hex(z_and),
    })

    vector["or"].append({
        "x": to_hex(x),
        "y": to_hex(y),
        "z": to_hex(z_or),
    })

# NOT is unary; cover a few fixed and random patterns
fixed_not = [
    b"",
    b"\x00",
    b"\xff",
    b"\x0f\xf0",
    b"\xaa\x55\x00\xff",
]

for x in fixed_not:
    z_not = bytes((~b & 0xFF) for b in x)
    vector["not"].append({
        "x": to_hex(x),
        "z": to_hex(z_not),
    })

for _ in range(16):
    length = random.randint(0, 64)
    x = rand_bytes(length)
    z_not = bytes((~b & 0xFF) for b in x)
    vector["not"].append({
        "x": to_hex(x),
        "z": to_hex(z_not),
    })

print(json.dumps(vector, indent=2))