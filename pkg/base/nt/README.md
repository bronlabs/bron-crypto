# nt - Number Theory

Foundational number theory primitives for cryptographic applications.

## Subpackages

- **numct** - Constant-time arbitrary precision integers (`Nat`, `Int`, `Modulus`)
- **num** - Typed number structures with algebraic semantics (`N`, `Z`, `Q`, `NatPlus`, `Uint`, `ZMod`)
- **cardinal** - Cardinal numbers for representing group orders (known, unknown, infinite)
- **modular** - Modular arithmetic with CRT optimization for prime factorizations
- **crt** - Machinery for Chinese Remainder Theorem
- **znstar** - Multiplicative unit groups `(Z/nZ)*` for RSA and Paillier cryptosystems

## Usage

```go
// Generate RSA primes
p, q, _ := nt.GeneratePrimePair(num.NPlus(), 1024, rand.Reader)

// Create an RSA group
rsa, _ := znstar.NewRSAGroup(p, q)

// Create a Paillier group
paillier, _ := znstar.NewPaillierGroup(p, q)
```
