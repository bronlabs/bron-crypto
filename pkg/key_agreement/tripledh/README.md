# The X3DH Key Agreement Protocol
The original protocol is outlined in [x3dh], however this package implements the variant suitable for [art] (see Chapter 6.3 Analysis: Authenticated Protocol).  
Namely, given identity keys (long term keys) of Alice and Bob ($a$, $b$ respectively), ephemeral keys of Alice and Bob ($x$, $y$ respectively), subgroup generator $G$ and hash function $H$ it computes (multiplicative notation):

$$ K = H\left(G^{ay} \mathrel{\Vert} G^{bx} \mathrel{\Vert} G^{xy} \mathrel{\Vert} G^{ab}\right) $$

and then $K$ is mapped to a uniformly random scalar using a hash-to-field algorithm.

[x3dh]: <https://signal.org/docs/specifications/x3dh/x3dh.pdf>
[art]: <https://eprint.iacr.org/2017/666.pdf>
