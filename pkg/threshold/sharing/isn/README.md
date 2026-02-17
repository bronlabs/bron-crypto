# Ito-Saito-Nishizeki replicated secret sharing scheme

Package isn implements the Ito-Saito-Nishizeki (ISN) secret sharing scheme for general monotone access structures.

The ISN scheme generalizes threshold secret sharing to arbitrary monotone access structures specified in either DNF (Disjunctive Normal Form) or CNF (Conjunctive Normal Form). Unlike Shamir's threshold scheme which only supports t-of-n access structures, ISN can handle complex authorization policies such as "any 2 executives OR any 3 managers" (DNF) or "at least one from each department" (CNF). Note that any access structure is representable in both DNF and CNF, but the choice of representation can impact the efficiency of share generation and reconstruction.

## Security

The ISN scheme provides information-theoretic security: any unauthorized coalition learns no information about the secret. Unlike polynomial-based schemes (Shamir, Feldman, Pedersen), ISN works directly over any finite group without requiring field arithmetic.

## Reference

- Section 4.2 of [B25](https://eprint.iacr.org/2025/518.pdf)
