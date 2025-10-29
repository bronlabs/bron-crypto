# Randomness Wrapper as per RFC 8937

It is possible that the CSPRNG is faulty due to hardware or other reasons. To mitigate this risk, we implement [RFC8937](https://datatracker.ietf.org/doc/html/rfc8937). This is essentially a randomness wrapper that ties the security of the CSPRNG to a deterministic signing key.

## Wrapper

` G'(n) = Expand(Extract(H(Sig(sk, tag1)), G(L)), tag2, n)`

- Let G(n) be an algorithm that generates n random bytes, i.e., the output of a CSPRNG.
- Let Sig(sk, m) be a function that computes a signature of message m given private key sk.
- Let H be a cryptographic hash function that produces output of length M.
- Let Extract(salt, IKM) be a randomness extraction function, e.g., HKDF-Extract, which accepts a salt and input keying material (IKM) parameter and produces a pseudorandom key of L bytes suitable for cryptographic use. It must be a secure PRF (for salt as a key of length M) and preserve uniformness of IKM. L SHOULD be a fixed length.
- Let Expand(k, info, n) be a variable-length output PRF, e.g., HKDF-Expand, that takes as input a pseudorandom key k of L bytes, info string, and output length n, and produces output of n bytes.
- let tag1 be a fixed, context-dependent string
- let tag2 be a dynamically changing string (e.g., a counter) of L' bytes


### Remarks:
- L >= n - L' for each value of tag2
- Re tag1: Constant string bound to a specific device and protocol in use. This allows caching of Sig(sk, tag1). Device-specific information may include, for example, a Media Access Control (MAC) address. To provide security in the cases of usage of CSPRNGs in virtual environments, it is RECOMMENDED to incorporate all available information specific to the process that would ensure the uniqueness of each tag1 value among different instances of virtual machines (including ones that were cloned or recovered from snapshots). This is needed to address the problem of CSPRNG state cloning (see [RY2010]). We relay this responsability to the user and instead require them to provide a unique "keyID".
- Re tag2: A nonce, that is, a value that is unique for each use of the same combination of G(L), tag1, and sk values. The tag2 value can be implemented using a counter or a timer, provided that the timer is guaranteed to be different for each invocation of G'(n). We use a timer.


### Presets
- H = Sha3-256
- N = 256
- L = 256
- L' = 256

