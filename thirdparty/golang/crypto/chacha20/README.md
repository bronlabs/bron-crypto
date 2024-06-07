# `chacha20` Fast-Erasure implementation of the ChaCha20 stream cipher

This package forks golang's `crypto/chacha20` implementation of the ChaCha20 stream cipher, enhancing it to frequently refresh the key and to immediately erase the buffer of generated randomness after each use, following [Daniel Bernstein's recommendations](https://blog.cr.yp.to/20170723-random.html).