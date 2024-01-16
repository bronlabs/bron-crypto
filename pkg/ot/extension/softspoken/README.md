# Softspoken OT Extension
Package `softspoken` implements of maliciously secure 1-out-of-2 Correlated Oblivious Transfer extension (COTe) protocol.

We follow the designs from:
- [SoftSpokenOT](https://eprint.iacr.org/2022/192) for the OT extension
- [MR19](https://eprint.iacr.org/2019/706) for the Derandomization ("Correlated")
We use the notation from ROT^{κ,l} from Figure 10 of [KOS15](https://eprint.iacr.org/2015/546)
for the protocol description. We apply the "Fiat-Shamir" heuristic,
replacing the coin tossing required for the consistency check with the
hash of the public transcript (using an (*) to denote the changes).

## Best-effort Constant Time implementation

The code of this package is written in a best-effort mode to be Constant Time by: 
1. Removing data-dependent branching (e.g. if-else statements) and data-dependent iteration (e.g. data-dependent length of for-loops)
2. Using constant-time operations from primitives (e.g. constant-time field operations from `saferith`)
3. Delaying error/abort raising when tied to data (e.g., for loops in consistency checks) to avoid leaking unnecessary stop information. Note that this does not cover "static" errors (e.g., wrong size for hashing).
4. Using `crypto/subtle` functions whenever applicable.