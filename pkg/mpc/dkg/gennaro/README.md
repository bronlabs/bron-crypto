# Gennaro DKG

Distributed key generation following Gennaro et al. ("Secure Distributed Key Generation for Discrete-Log Based Cryptosystems", EUROCRYPT 1999), with three departures from the original paper.

## Differences from the original Gennaro paper

1. **Generic monotone access structures via MSPs**. The original protocol is restricted to (t, n) threshold access structures backed by Shamir/Pedersen polynomial sharing. This implementation replaces the polynomial layer with the KW MSP-based LSSS, so any monotone access structure that admits a monotone span programme — threshold, unanimity, CNF, hierarchical conjunctive, boolean-expression, etc. — works without protocol changes. The resulting shard is an `mpc.BaseShard` tied to the MSP induced from the supplied access structure.

2. **Okamoto proofs of knowledge of opening for the Pedersen verification vector**. Each dealer attaches a non-interactive batch Okamoto proof (one Okamoto sigma per coefficient, AND-composed) showing that it knows `(c_j, b_j)` such that `V_j = [c_j]G + [b_j]H` for every coefficient of its Pedersen verification vector. This binds the dealer's commitments and prevents dishonest broadcast of unopenable verification vectors.

3. **Batch Schnorr proof of knowledge of Feldman coefficients' discrete logs**. Once the Pedersen layer is accepted, each party derives its Feldman verification vector by lifting the secret column to the exponent and broadcasts it together with a non-interactive batch Schnorr proof of knowledge of the discrete log of every Feldman coefficient. The batch proof has the same soundness as `D` independent Schnorr proofs while keeping size and verification cost compact.

## Protocol Outline

The implementation is three rounds. Aborts are identifiable: failed proofs and bad shares are tagged with the offending party's ID via `base.IdentifiableAbortPartyIDTag`.

### Round 1 — Pedersen dealing + Okamoto PoK

Each party:

1. Deals a fresh Pedersen sharing of a random secret over the access structure (random column `c` for the secret, random column `b` for the blinding) and computes `V_pedersen[j] = [c_j]G + [b_j]H`.
2. Privately sends each receiver its Pedersen share `(λ_g_i, λ_h_i)` via unicast.
3. Computes a non-interactive batch Okamoto proof — one Okamoto sigma per coefficient, AND-composed via `sigand` and Fiat-Shamir-compiled — showing knowledge of `(c_j, b_j)` for every Pedersen verification vector coefficient.
4. Broadcasts `(V_pedersen, π_okamoto)`.

### Round 2 — Pedersen verification + Feldman dealing + batch Schnorr PoK

Each party:

1. For every other party, verifies the batch Okamoto proof against their broadcast Pedersen verification vector. A bad proof aborts with that party's ID.
2. Verifies the Pedersen share received via unicast against the broadcast Pedersen verification vector.
3. Accumulates accepted shares into a running sum `summedShareValue` (this becomes the final share value).
4. Derives its Feldman verification vector from its own Pedersen secret column by lifting it to the exponent: `V_feldman[j] = [c_j]G`.
5. Computes a non-interactive batch Schnorr proof of knowledge of the discrete log of every Feldman verification vector coefficient.
6. Broadcasts `(V_feldman, π_schnorr)`.

### Round 3 — Feldman verification + aggregation

Each party:

1. Verifies every other party's batch Schnorr proof against their Feldman verification vector. A bad proof aborts with that party's ID.
2. For every other party, lifts the previously-received Pedersen share to a Feldman share and verifies it against the broadcast Feldman verification vector. A bad share aborts with that party's ID.
3. Sums all Feldman verification vectors into the joint Feldman verification vector.
4. Returns an `mpc.BaseShard` carrying the summed share value, the summed Feldman verification vector, and the MSP matrix.

## Usage

1. Build a `session.Context` for each party and choose any monotone access structure.
2. Create a `Participant` with `NewParticipant`, or use `NewRunner` for fully-managed execution over a `network.Router`.
3. Drive `Round1` → `Round2` → `Round3`, exchanging the broadcasts and Round 1 unicasts in between.
4. The Round 3 output is the per-party `mpc.BaseShard`; all parties' shards share the same Feldman verification vector and reconstruct to the same secret.

## Reference

- Gennaro, R., Jarecki, S., Krawczyk, H., and Rabin, T. "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems." EUROCRYPT, 1999.
- Karchmer, M. and Wigderson, A. "On Span Programs." Structure in Complexity Theory Conference, 1993.
- Okamoto, T. "Provably Secure and Practical Identification Schemes and Corresponding Signature Schemes." CRYPTO, 1992.
