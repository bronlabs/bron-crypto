# bron-crypto

Bron's Advanced Cryptography Library

This library provides implementations of state-of-the-art cryptographic protocols, written by cryptographers for cryptographers, using modern software engineering practices. Our approach is characterized by the following principles:

1. **Redundancy**: Since we operate at the frontier of cryptographic research rather than in the domain of "settled" cryptography, we plan for yet-unknown protocol-level vulnerabilities by providing alternative implementations that rely on different cryptographic assumptions and tools.

2. **Reusability**: Cryptography code is typically written once, audited, and then forgotten. We aim for reusability through modular design. For example, our sigma protocols can be made non-interactive using different compilers or composed together with minimal additional code. Similarly, our CRT package is implemented independently so that both Paillier and RSA can use it.

## Focus

The primary focus of this library is MPC (Multi-Party Computation), specifically threshold signing. We support the following protocols:

- **Threshold Schnorr**: Lindell22
- **Threshold ECDSA**: DKLs23 and Lindell17. We provide three variants of DKLs23: one using OT extensions (compatible with the paper), one without OT extensions, and one that generates base OT during signing.
- **Threshold BLS**: Boldyreva02

## Security Notice

This library is not designed to be fully side-channel resistant. We build higher-level protocols on top of a side-channel resistant foundation of elliptic curve and big integer operations.

**Important**: This library is intended for use by experienced cryptographers and developers who understand the security implications of the protocols involved. If you are not familiar with the underlying cryptographic primitives, please consult with a cryptography expert before using this library in production.

## Installation

```bash
go get github.com/bronlabs/bron-crypto
```

Note: This library requires CGO and links against BoringSSL. See [DEVELOPMENT.md](./DEVELOPMENT.md) for build prerequisites and setup instructions.

## Development

To set up the repository for development, see [DEVELOPMENT.md](./DEVELOPMENT.md).

## Maintainers

- [Alireza Rafiei](https://www.linkedin.com/in/alireza-rafiei/)
- [Mateusz Kramarczyk](https://www.linkedin.com/in/mateusz-kramarczyk-9b211125/)

### Alumni

- [Alberto Ibarrondo Luis](https://www.linkedin.com/in/albertoibarrondo/)
- [Hoang Ong](https://www.linkedin.com/in/hoangong/)
- [Paul Germouty](https://www.linkedin.com/in/paul-germouty-01506314a/)
- [Alexandre Adomnicai](https://www.linkedin.com/in/alexandre-adomnicai/)
- [Mohammad Sarraf](https://www.linkedin.com/in/mohammad-sarraf/)

## License

SPDX-License-Identifier: Apache-2.0

See [LICENSE](./LICENSE) and [thirdparty/NOTICE](thirdparty/NOTICE) files for details.
