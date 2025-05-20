# BIP-32 like derivation
We follow a similar approach to [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) for
deterministic extended shard derivation from the root shard.
If the shard curve is K-256 (aka secp256k1) we follow BIP-32 normal derivation exactly, which is:

The function CKDpub((K<sub>par</sub>, c<sub>par</sub>), i) &rarr; (K<sub>i</sub>, c<sub>i</sub>) computes a child extended public key from the parent extended public key. It is only defined for non-hardened child keys.
* Check whether i ≥ 2<sup>31</sup> (whether the child is a hardened key).
  ** If so (hardened child): return failure
  ** If not (normal child): let I = HMAC-SHA512(Key = c<sub>par</sub>, Data = ser<sub>P</sub>(K<sub>par</sub>) || ser<sub>32</sub>(i)).
* Split I into two 32-byte sequences, I<sub>L</sub> and I<sub>R</sub>.
* The returned child key K<sub>i</sub> is point(parse<sub>256</sub>(I<sub>L</sub>)) + K<sub>par</sub>.
* The returned chain code c<sub>i</sub> is I<sub>R</sub>.
* In case parse<sub>256</sub>(I<sub>L</sub>) ≥ n or K<sub>i</sub> is the point at infinity, the resulting key is invalid, and one should proceed with the next value for i.

For the other curves the process is almost the same with the following changes:
* instead of HMAC-SHA512 the Blake2b XOF is used (in MAC mode) from which the arbitrary number of bytes can be extracted
* I<sub>L</sub> length is twice as long as the curve's order length and is then reduced modulo curve order (this is done)
  to avoid bias when reducing it.
* point serialization depends on the curve and is chosen accordingly

When these changes are incorporated, the procedure is as follows (q is the curve order):

* Check whether i ≥ 2<sup>31</sup> (whether the child is a hardened key).
  ** If so (hardened child): return failure
  ** If not (normal child): let I = Blake2b(Key = c<sub>par</sub>, Len = 2*len(q) + 32, Data = ser<sub>P</sub>(K<sub>par</sub>) || ser<sub>32</sub>(i)).
* Split I into two ((2*len(q))-byte and 32-byte) sequences, I<sub>L</sub> and I<sub>R</sub>.
* The returned child key K<sub>i</sub> is point(parse<sub>2*len(q)</sub>(I<sub>L</sub>) mod q) + K<sub>par</sub>.
* The returned chain code c<sub>i</sub> is I<sub>R</sub>.
* In case K<sub>i</sub> is the point at infinity, the resulting key is invalid, and one should proceed with the next value for i.

This algorithm is also inline with HDWal[RSig].PKDer<sub>NH</sub> algorithm from
[The Exact Security of BIP32 Wallets](https://eprint.iacr.org/2021/1287.pdf) where:
* Blake2b is used as H 
* additive randomization i.e. point addition (pk + point(ω)) is used as RSig.RandPK(pk; ω)
