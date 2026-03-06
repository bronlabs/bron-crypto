# PRZS

Pseudorandom (non-interactive) zero sharing.
Provides deterministic sampling so parties can generate additive zero-sum shares without interaction after setup.

## Components

- **Seed Setup** (`przs/setup`): commit-and-reveal protocol that establishes pairwise seeds.
- **Sampler**: uses established seeds to deterministically derive zero-sum shares via ChaCha8 PRNGs.

## Usage

1. Run the seed setup protocol to obtain `przs.Seeds`.
2. Instantiate `Sampler` with `NewSampler(sharingID, quorum, seeds, field)`.
3. Call `Sample` to derive your zero-share; all parties’ samples sum to zero.
