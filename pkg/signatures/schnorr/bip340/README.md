## Bitcoin Schnorr Signature

This package implements the Schnorr signature algorithm, as specified in [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).

You can find all details in the BIP docs. This readme only contains an overview of the API.

### Sign

```
Input:
    The secret key sk: a 32-byte array
    The message m: a byte array
    Auxiliary random data a: a 32-byte array
    
The algorithm Sign(sk, m) is defined as:
    1. Let d' = int(sk)
    2. Fail if d' = 0 or d' ≥ n
    3. Let P = d'⋅G
    4. Let d = d' if has_even_y(P), otherwise let d = n - d' .
    5. Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a).
    6. Let rand = hashBIP0340/nonce(t || bytes(P) || m).
    7. Let k' = int(rand) mod n.
    8. Fail if k' = 0.
    9. Let R = k'⋅G.
    10. Let k = k' if has_even_y(R), otherwise let k = n - k' .
    11. Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.
    12. Let sig = bytes(R) || bytes((k + ed) mod n).
    13. If Verify(bytes(P), m, sig) (see below) returns failure, abort[14].
    14. Return the signature sig.
```

* Specs in some other websites also check if message is 32 bytes. That is because transaction hash in bitcoin is 32 bytes. If we want to use this as general purpose we don't have to have that check. I didn't check message size in this implementation.
* There are deterministic and non-deterministic signing. That depends on Aux variable. In the docs, it assumes that client provides a random aux to generate non-deterministic signed signature. In this implementation if aux is nil, it will generate k which is non-deterministic.

### Verify

```
Input:
    The public key pk: a 32-byte array
    The message m: a byte array
    A signature sig: a 64-byte array

The algorithm Verify(pk, m, sig) is defined as:
    1. Let P = lift_x(int(pk)); fail if that fails.
    2. Let r = int(sig[0:32]); fail if r ≥ p.
    3. Let s = int(sig[32:64]); fail if s ≥ n.
    4. Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
    5. Let R = s⋅G - e⋅P.
    6. Fail if is_infinite(R).
    7. Fail if not has_even_y(R).
    8. Fail if x(R) ≠ r.
Return success iff no failure occurred before reaching this point.
For every valid secret key sk and message m, Verify(PubKey(sk),m,Sign(sk,m)) will succeed.
```

* Verify in the docs use hash

### Batch Verify

```
Input:
    The number u of signatures
    The public keys pk1..u: u 32-byte arrays
    The messages m1..u: u byte arrays
    The signatures sig1..u: u 64-byte arrays
    
The algorithm BatchVerify(pk1..u, m1..u, sig1..u) is defined as:
    1. Generate u-1 random integers a2...u in the range 1...n-1. They are generated deterministically using a CSPRNG seeded by a cryptographic hash of all inputs of the algorithm, i.e. seed = seed_hash(pk1..pku || m1..mu || sig1..sigu ). A safe choice is to instantiate seed_hash with SHA256 and use ChaCha20 with key seed as a CSPRNG to generate 256-bit integers, skipping integers not in the range 1...n-1.
    For i = 1 .. u:
    2. Let Pi = lift_x(int(pki)); fail if it fails.
    3. Let ri = int(sigi[0:32]); fail if ri ≥ p.
    4. Let si = int(sigi[32:64]); fail if si ≥ n.
    5. Let ei = int(hashBIP0340/challenge(bytes(ri) || bytes(Pi) || mi)) mod n.
    6. Let Ri = lift_x(ri); fail if lift_x(ri) fails.
    7. Fail if (s1 + a2s2 + ... + ausu)⋅G ≠ R1 + a2⋅R2 + ... + au⋅Ru + e1⋅P1 + (a2e2)⋅P2 + ... + (aueu)⋅Pu.
    Return success iff no failure occurred before reaching this point.
```

* The only difference from the docs is in step 2, instead of using `ChaCha20` hashing I used transcript.
