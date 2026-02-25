# signing

Interactive signing protocol for Lindell22 threshold Schnorr.

## Overview

Implements the 3-round interactive signing protocol from Lindell 2022. Each round involves broadcasting messages to all parties in the signing quorum.

## Protocol Rounds

1. **Round 1**: Sample random nonce, commit to it, broadcast commitment
2. **Round 2**: Receive commitments, broadcast nonce with discrete log proof
3. **Round 3**: Verify commitments and proofs, compute partial signature
