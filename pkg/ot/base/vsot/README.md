# `vsot`: Verified Simplest Oblivious Transfer
This package implements the "Verified Simplest OT", as defined in "protocol 7" of[DKLs18](https://eprint.iacr.org/2018/499.pdf).
The original "Simplest OT" protocol is presented in [CC15](https://eprint.iacr.org/2015/267.pdf). In our implementation, we run OTs for multiple 
choice bits in parallel. Furthermore, as described in the DKLs18 paper,
we implement this as Randomized OT (ROT) protocol. We keep the encryption and decryption steps (9 and 10)
from the original protocol to realize a standard OT, highlighting that ROT (steps 1 to 8) suffices 
when VSOT is used as Base OT in an OT extension protocol such as SoftspokenOT (in `pkg/ot/extension/softspoken`).

Limitation: currently we only support batch OTs that are multiples of 8.