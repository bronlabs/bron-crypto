# PRZS

Pseudorandom (non-interactive) zero sharing.
Provides deterministic sampling so parties can generate additive zero-sum shares without interaction, given pairwise seeds from a `session.Context`.

## Usage

1. Run the session setup protocol to obtain a `session.Context` with pairwise seeds.
2. Call `SampleZeroShare(ctx, group)` to derive your additive zero-share; all parties’ samples sum to the group identity.
