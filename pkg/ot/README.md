# `ot`: 1-out-of-2 Oblivious Transfer

This package holds the types shared by the oblivious-transfer protocols of its
subpackages and the subpackages themselves:

- `base/mrr21`: the one-round-trip batched endemic base OT of Masny, Rindal and Roy,
  from a tagged Diffie–Hellman key agreement and a programmable-once public function.
- `extension/iknp03`: the semi-honest IKNP03 correlated OT extension, $F_{COTe}$, built
  on κ base OTs with the roles reversed.
- `extension/softspoken`: the maliciously secure random OT extension of KOS15 Figure 10
  with the SoftSpokenOT consistency check under Fiat–Shamir, on top of `iknp03`.

## Common types

- `Choices` is a packed little-endian bit vector of receiver choice bits.
- `Message` is the constraint on OT messages, satisfied by the fixed-width arrays
  `Message128` and `Message256`; `MessageBitLen` and `MessageAsSlice` read the width
  and view an array as bytes without copying.
- `SenderOutput[M]` holds both messages of every OT, `SenderCorrelatedOutput[M]` the
  rows and the correlation $Δ$ of a correlated extension, `ReceiverOutput[M]` the
  choice bits and the received messages. All three serialise to CBOR as byte slices and
  reject any message whose width is not that of `M` on decoding.

## Composition

`mrr21` produces `Message128` seeds; `iknp03` consumes κ = 128 or 256 of them, fixed
by its output type, and `softspoken` consumes exactly 128 to produce 128-bit random
OTs. The random vector OLE of `mpc/rvole` runs on either `softspoken` or directly on
`mrr21` with 256-bit messages, and DKLs23 signing has an instantiation on each. Every protocol
runs on a two-party session and binds its messages to the session transcript before
deriving anything from it.

## References

Each subpackage README cites its papers.
