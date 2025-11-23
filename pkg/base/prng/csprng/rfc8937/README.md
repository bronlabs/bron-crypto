# Randomness Wrapper as per RFC 8937

It is possible that the CSPRNG is faulty due to hardware or other reasons. To mitigate this risk, we implement [RFC8937](https://datatracker.ietf.org/doc/html/rfc8937). This is essentially a randomness wrapper that ties the security of the CSPRNG to a deterministic signing key.

### Presets
- H = Sha3-256
- N = 256
- L = 256
- L' = 256

