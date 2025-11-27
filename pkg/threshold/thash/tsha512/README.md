# Threshold SHA-512 (POC)
The protocol returns the 2-of-3 shares of random preimage (32-bytes length)
and the shares of sha-512(preimage) of length 64-bytes.

It is a proof of concept far from being optimal (it requires ca. 10k rounds)
and is only a semi-honest, although it would be relatively easy to make it
honest-majority maliciously secure without much communication overhead:
* https://eprint.iacr.org/2023/909 or
* https://eprint.iacr.org/2019/658

Locally it runs in ~300ms but over the network it would be two orders of magnitude slower.