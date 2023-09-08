# Krypton DKG Bundle

Copper's current custodial offering for tecdsa is a (2,3) mpc protocol primarily using DKLs23. We also have a backup protocol that we can swap to at the SDK level, based on Lindell17.

This Bundle first runs the agree on random protocol to derive a unique session ID, then initializes DKG subprotocols of DKLs23 and Lindell17 and runs them in parallel.

Note that we still will have a single signing share, however DKLs23 requires machinery for zero share sampling and base OTs, and Lindell17 requires pairwise paillier encryption of the shares. So we are starting the DKLs23 DKG first, until we get the signing share. Afterwards, we'll continue with DKLs23 and Lindell17 in parallel.

The result is an 11 round protocol where each round concerns the following (in the order of evaluation):

- Round 1:
  - Agree on random
- Round 2:
  - Agree on random
  - DKLs23
- Round 3:
  - DKLs23
- Round4:
  - DKLs23
  - Lindell17
- Round5:
  - DKLs23
  - Lindell17
- Round6:
  - DKLs23
  - Lindell17
- Round7:
  - Lindell17
- Round8:
  - Lindell17
- Round9:
  - Lindell17
- Round10:
  - Lindell17
- Round11:
  - Lindell17
