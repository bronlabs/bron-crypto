# bf128 — GF(2^128) Binary Extension Field

This package implements arithmetic over the binary extension field GF(2^128), constructed as:

```
GF(2)[X] / (X^128 + X^7 + X^2 + X + 1)
```

The irreducible polynomial `f(X) = X^128 + X^7 + X^2 + X + 1` is sourced from Table A.1 of *Guide to Elliptic Curve Cryptography* (Hankerson, Menezes, Vanstone).

## Field properties

| Property | Value |
|---|---|
| Order | 2^128 |
| Characteristic | 2 |
| Extension degree over GF(2) | 128 |
| Irreducible polynomial | X^128 + X^7 + X^2 + X + 1 |

Because the characteristic is 2:

- **Addition = Subtraction = XOR.** Every element is its own additive inverse.
- **Negation is the identity function.** `-a = a` for all `a`.

## Internal representation

A field element is stored as `[2]uint64` in little-endian limb order:

- `el[0]` holds bits 0–63 (coefficients of X^0 through X^63)
- `el[1]` holds bits 64–127 (coefficients of X^64 through X^127)

Bit `i` within the limbs is the coefficient of X^i in the polynomial representation.

## Serialisation

### Bytes (16-byte encoding)

`Bytes()` and `FromBytes()` use big-endian byte order: the first byte contains the most significant bits (coefficients of X^127 down to X^120).

### Component bytes (128-element bit encoding)

`ComponentsBytes()` and `FromComponentsBytes()` represent the element as 128 individual GF(2) coefficients in **big-endian** order:

- Component 0 is the coefficient of X^127 (MSB)
- Component 127 is the coefficient of X^0 (LSB)
- Each component is a single byte: `0x00` or `0x01`

For example, the element `5` (binary `101`) has components:

```
components[0..124] = 0
components[125]    = 1   (coefficient of X^2)
components[126]    = 0   (coefficient of X^1)
components[127]    = 1   (coefficient of X^0)
```

## Arithmetic operations

| Operation | Method | Notes |
|---|---|---|
| Addition | `Add` | Bitwise XOR |
| Subtraction | `Sub` | Same as `Add` (char 2) |
| Negation | `Neg` | Identity function (char 2) |
| Multiplication | `Mul` | Shift-and-XOR with modular reduction |
| Squaring | `Square` | Via `Mul` |
| Inversion | `TryInv` | Extended Euclidean algorithm for binary polynomials |
| Division | `TryDiv` | Multiply by inverse |

Multiplication uses the shift-and-XOR algorithm from Section 2.3 of *Guide to Elliptic Curve Cryptography*, with stacked modular reduction per Algorithm 2.40 / Figure 2.9.

Inversion uses the binary polynomial extended Euclidean algorithm to find `b` such that `b * el = 1 mod f(X)`.

## Usage

```go
f := bf128.NewField()

// Random element
a, _ := f.Random(prng)

// Arithmetic
b, _ := f.RandomNonZero(prng)
sum := a.Add(b)
product := a.Mul(b)
inverse, _ := b.TryInv()

// Serialisation
bytes := a.Bytes()               // 16-byte big-endian
components := a.ComponentsBytes() // 128 single-byte GF(2) coefficients

// Reconstruction
a2, _ := f.FromBytes(bytes)
a3, _ := f.FromComponentsBytes(components)
```
