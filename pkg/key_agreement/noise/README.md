# Noise Protocol

This package implements noise protocol explained in [Noise Protocol Framework](http://noiseprotocol.org/noise.html).

We implement the following patterns:

* [K Pattern](https://noiseexplorer.com/patterns/K/) for non-interactive key exchange

```
K:
  -> e, es, ss
```

* [KK Pattern](https://noiseexplorer.com/patterns/KK/) for interactive key exchange (2 rounds)

```
KK:
  -> e, es, ss
  <- e, ee, se
```

* For both patterns, we assume that all party members know each other's long-term public keys.

# References

* Flexible Authenticated and Confidential Channel Establishment (fACCE): Analyzing the Noise Protocol Framework by Benjamin Dowling at al - <https://eprint.iacr.org/2019/436.pdf>
* A Spectral Analysis of Noise: A Comprehensive, Automated Formal Analysis of Diffie-Hellman-based Protocols by Cremers et al - <https://people.cispa.io/cas.cremers/downloads/papers/Noise-Usenix2020.pdf>
* Noise*: A Library of Verified High-Performance Secure Channel Protocol Implementations by Almeida et al - <https://eprint.iacr.org/2022/607.pdf>
* Wireguard formal verification - <https://www.wireguard.com/papers/wireguard-formal-verification.pdf>
