# CGGMP21 Aux-Info protocol

Distributed generation of the CGGMP21 auxiliary information — each party's
Paillier key and ring-Pedersen parameters — that threshold ECDSA presigning
needs. It runs on top of an already-shared key: it consumes a base shard (e.g.
from the Canetti DKG) and returns it augmented with the agreed auxiliary info.

Note that we deviate from the paper by removing the key-refresh pieces of
Figure 7. To re-randomise the secret shares, run the `redistribute` protocol
from this repository.

## Protocol

Four rounds, identifiable abort on any failed check:

| Round | Action |
| ------- | -------- |
| 1 | Sample Paillier key `Nᵢ` and ring-Pedersen `(N̂ᵢ, sᵢ, tᵢ)`, prove the latter well-formed (`Π_prm`), draw a `rid` share, broadcast a hash commitment to all of it |
| 2 | Broadcast the opening of the commitment |
| 3 | Verify openings + `Π_prm`, set `rid = ⊕ⱼ ridⱼ`, send the Paillier-Blum proof (`Π_mod`) and a per-verifier no-small-factor proof (`Π_fac`) |
| 4 | Verify all `Π_mod`/`Π_fac`, output the base shard plus auxiliary info |

The round-1 commit-then-reveal binds each party's contribution before openings
are seen; `rid` is folded into the proof contexts as a fresh shared domain
separator. `Π_fac` is bound to the *verifier's* ring-Pedersen setup, so it is
distinct per recipient; `Π_mod` is verifier-independent.

## Reference

<!-- paper: docs/papers/2021-060_20241021_172019.pdf [Section 4.2, Figure 7]-->
- Canetti, Gennaro, Goldfeder, Makriyannis, Peled. [UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts](https://eprint.iacr.org/2021/060),
  Section 4.2, Figure 7.
