# `ecbbot`: Batching Base Oblivious Transfers
This package implements the "Batched Simplest OT", an OT protocol with endemic security defined in Figure 3 of
[MRR21](https://eprint.iacr.org/2021/682), to run Random OTs (ROT) for a batch of choice bits in parallel. 

This is essentialy almost the same as `bbot` package but the messages' domains are $Z_q$.
