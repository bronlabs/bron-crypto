---
name: constant-time-check
description: Audit code for timing side-channels — variable-time operations on secret values. Use when the user asks to check constant-time, timing, or side-channel safety of a file, function, or diff in this repo.
effort: max
---

You are checking whether code introduces timing leaks on secret data. Be specific, cite `file:line`, and don't fix — report.

## Library context (read once)

- `README.md` / `SECURITY.md`: this library is **not** fully side-channel resistant. The CT foundation is in `pkg/base/curves/**/impl/` (fiat-crypto), `pkg/base/cgo/boring/` (BoringSSL), and `pkg/base/nt/numct/` (saferith/BoringSSL wrapper). Higher protocols are built on top.
- Timing attacks are **out of scope for the bug bounty** (`SECURITY.md`), but new timing leaks in otherwise constant-time packages are considered as a vulnerability. Treat them as findings.

## What counts as "secret"

Anything that, if leaked bit-by-bit, breaks the protocol. In this repo:
- Private keys, signing nonces (`k`), additive / Shamir shares, blinding factors.
- Pedersen / paillier / ZK witnesses
- Trapdoors (`λ`, `ϕ(N)`, RSA primes `p`/`q`)
- Encryption ephemerals, Diffie–Hellman secrets
- Decrypted plaintext where confidentiality matters
If you're unsure whether a value is secret, *say so* in the finding rather than silently exclude it.

## Steps

1. Identify the target (file / package / diff). Determine audit scope: is it reachable from `pkg/mpc/signatures/**` or transitively depended on by it? In-scope code gets the higher bar.
2. List the secret values in the function. For each one, check the patterns below.
3. Output findings as a flat list with severity.

## Patterns to flag (with the right replacement)

### Branching on secrets

- `if secret == 0 { … }`, `switch secret { … }`, ternary-like `if cond { x } else { y }` where `cond` depends on a secret.
- Loops with secret-dependent length or early exit: `for secret > 0`, `for i, b := range secretBytes { if b != 0 { break } }`.
- **Use**: `pkg/base/ct` — `ct.IsZero`, `ct.Equal`, `ct.Less[OrEqual]`, `ct.Greater[OrEqual]`, `ct.Choice`, `ct.CSelectInt`, `ct.CMOVInt`, `ct.CSwapInt`. For byte/slice ops: `ct.SliceEqual`, `ct.SliceIsZero`, `ct.CSelectInts`.

### Variable-time big-integer arithmetic on secrets

- `math/big.Int`, `math/big.NewInt`, `math/big.Exp`, `Mod`, `ModInverse`, `Cmp` are all variable time. Same for `pkg/base/nt/num` (the variable-time signed-int wrapper).
- **Use**: `pkg/base/nt/numct` (constant-time `Nat` / `Modulus` / `Int`) for any value that holds or is derived from a secret. Particularly `numct.Modulus.Exp`, `numct.Nat.ModInverse`, `numct.Nat.Mod`.
- `*big.Int.Bit(i)`, `.BitLen()` — variable-time on a secret leaks the magnitude; flag.
- Modular exponentiation with a secret exponent must be CT and (where the modulus has unknown order) blinded. Check the call site uses `numct` and not `num` / `math/big`.

### Equality on byte buffers

- `bytes.Equal(a, b)`, `==` on `[N]byte`, `string(a) == string(b)` — variable-time.
- **Use**: `crypto/subtle.ConstantTimeCompare` (stdlib, fixed-length) or `pkg/base/ct.SliceEqual` (any length, returns `Choice`).

### Table / array lookup by a secret index

- `table[secretIndex]`, `arr[secretByte]`, `slice[secret % len]` — leaks via cache.
- **Use**: linear scan with `ct.CSelect…` to fold all entries.

### Conditional negate / select / swap implemented as `if`

- `if neg { x = x.Neg() }`, `if cond { swap(a, b) }`.
- **Use**: `ct.ConditionallyNegatable` interface implementations (`numct.Int` provides one) or `ct.CMOVInt` / `ct.CSwapInt`.

### Secret-dependent allocation or length

- `make([]byte, secretLen)`, `append(buf, secret...)` where caller can observe size.
- Pad to a fixed length, or work in-place on a fixed-size buffer.

### Secret-dependent error returns / early returns

- `if invalid { return ErrFoo }` where `invalid` depends on a secret in a way that distinguishes which check failed.
- For decryption / verification, prefer one error code that doesn't reveal *which* check failed (think padding-oracle).

### Logging / formatting / Stringer on secrets

- `fmt.Print*(secret)`, `slog.Info(... "key", secret)`, `secret.String()`.
- Secret types should override `String()` to redact (e.g., return `"<redacted>"`), and not satisfy `fmt.Stringer` accidentally via a wrapped field.

### Hash / KDF inputs whose *length* is secret

- Feeding `len(secret)` bytes into a sponge / merkle-damgård hash leaks the length via timing of the absorb loop. Use a fixed-size canonical encoding.

### Loops over public-and-secret zipped data

- `for i := range pub { if pub[i] != secret[i] { return false } }` — leaks the index of the first difference.
- **Use**: `ct.SliceEqual` or accumulate XORs and compare to zero with `ct.IsZero` at the end.

### Calls into variable-time primitives

- `crypto/elliptic` (the deprecated curve API) is variable-time on most curves.
- **Use**: this repo's curve packages (`pkg/base/curves/k256`, `…/edwards25519`, `…/p256`, etc.) which build on fiat-crypto / BoringSSL.

## What is acceptable

- Branching on **public** values (group order `n`, public key `P`, public message `m`, hash output of public data).
- Early exit when the secret has already been spent / committed (e.g., after the response `s` is published).
- `if err != nil { … }` — `err` is not secret as long as the error doesn't encode a secret and has no stack traces.

## Output format

Output as GitHub-flavoured markdown. Use headers, **bold** severity tags, and `code` spans for paths and replacements so the terminal renders a clear visual hierarchy. Don't wrap the whole report in a fenced code block. Template:

```
## Constant-time check — <target>

**Scope:** in-scope — _or_ — experimental
**Secrets identified:** `secret1`, `secret2`, …

### Findings

- **[critical]** `file.go:42` — short description
  - _Replace with:_ `ct.Foo`
- **[major]** `file.go:99` — short description
  - _Replace with:_ `numct.Bar`
- **[minor]** `file.go:120` — short description
  - _Replace with:_ ...
- **[question]** `file.go:150` — value may be secret; needs caller-side confirmation

_(If none: "No findings.")_

### Summary

**Counts:** N critical, N major, N minor, N question.
```

Severity tags must be one of `[critical]`, `[major]`, `[minor]`, `[question]` and always bolded. Order findings by severity (critical first), then by file path.

## Don'ts
- Don't claim a value is constant-time without verifying the underlying implementation. If you're unsure whether `numct.Nat.Foo` is CT, say so and link to the source line.
- Don't propose `crypto/subtle.ConstantTimeCompare` for variable-length inputs — it requires equal lengths; `ct.SliceEqual` is the safer default.
- Don't suggest "just remove the branch" without giving a CT replacement.
- Don't edit the code — this is an audit, not a fix.
