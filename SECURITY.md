# Security Notice

This library is not designed to be fully side-channel resistant. We build higher-level protocols on top of a side-channel resistant foundation of elliptic curve and big integer operations.

**Important**: This library is intended for use by experienced cryptographers and developers who understand the security implications of the protocols involved. If you are not familiar with the underlying cryptographic primitives, please consult with a cryptography expert before using this library in production.

**Audit**: The threshold signing packages of this library and all their direct and indirect dependencies have been audited by [Trail of Bits](https://github.com/trailofbits/publications?tab=readme-ov-file#cryptography-reviews) and the audit report may be found in the [audits](./audits/) directory.

## Supported Versions

Security updates are applied only to the most recent release. We recommend always using the latest version
of `bron-crypto` to ensure you have the most recent security patches.

## Reporting a Vulnerability

We take security vulnerabilities in `bron-crypto` very seriously. If you have discovered a security vulnerability,
please report it privately using one of the methods below. **Do not disclose it as a public issue or pull request.**

### How to Report

#### Preferred Method: GitHub Security Advisories

We use GitHub's private vulnerability reporting feature for coordinated disclosure. This allows us to:

- Privately discuss the vulnerability with you
- Collaborate on fixes in a temporary private fork (visible only to you and our security team)
- Prepare a patch before public disclosure

Please report vulnerabilities using GitHub Security Advisories:
**[Report a Security Vulnerability](https://github.com/bronlabs/bron-crypto/security/advisories/new)**

#### Alternative Method: Email

If you cannot use GitHub Security Advisories, you can email us directly at:
**[bugbounty@bron.org](mailto:bugbounty@bron.org)**

Please use the [Vulnerability Report Template](https://bugbounty.bron.org/report) when submitting your report.
The template includes the required format for email subject and body, ensuring all necessary information is included for efficient triage.

### What Happens Next

1. **Acknowledgment**: We will acknowledge receipt of your report within **3 business days**
2. **Initial Triage**: We will perform initial triage within **10 business days**
3. **Collaboration**: We may create a temporary private fork to collaborate on a fix with you
4. **Fix Development**: We will work with you to develop and test a fix
5. **Disclosure**: Once a patch is ready, we will coordinate public disclosure

### Responsible Disclosure Timeline

We request that you give us **at least 90 days** to work on a fix before public exposure. This timeline may be extended
for complex vulnerabilities requiring significant architectural changes.

## Bug Bounty Program

This repository is part of the **Bron Bug Bounty Program**. Security vulnerabilities reported through the proper
channels may be eligible for rewards.

### Program Details

- **Program Page**: [https://bugbounty.bron.org/](https://bugbounty.bron.org/)
- **Policy**: [Responsible Vulnerability Disclosure Policy](https://bugbounty.bron.org/policy)
- **Rewards**: See [Rewards Table](https://bugbounty.bron.org/rewards) for CVSS v4.0-based reward ranges
- **Scope**: This MPC cryptography library is in scope for the bug bounty program

### Eligibility

To be eligible for bug bounty rewards:

- You must be the first to report the vulnerability
- You must follow responsible disclosure practices (no public disclosure before patch release)
- The vulnerability must be in scope (see below)
- You must comply with the program's terms and conditions

## Scope

### In Scope

The bug bounty program covers security vulnerabilities in:

- Threshold signature schemes and their direct or indirect dependencies
- Cryptographic implementation flaws in production code
- Memory safety issues
- Logic errors in threshold signature schemes
- Issues in key generation, signing, or verification protocols
- Vulnerabilities in the BoringSSL integration

### Experimental Features

**Important:** Everything that is not a direct or indirect dependency of threshold signature schemes is considered
experimental and is **not part of the bug bounty program**.

We will introduce a more explicit way of handling experimental features in the future. For now, this policy serves
to clearly define the scope of our bug bounty program.

### Out of Scope

- Vulnerabilities in third-party dependencies (unless they create a bron-crypto-specific security issue)
- Issues that require physical access to the device
- Remote timing attacks
- Social engineering attacks
- Denial of service (DDoS) attacks that do not compromise security
- Issues in example code or documentation that do not affect the core library
- Vulnerabilities in applications using `bron-crypto` (report to those projects instead)

## Security Best Practices

When using `bron-crypto` in production:

- Always use the latest released version
- Review and follow our [documentation](README.md) for secure usage patterns
- Keep your dependencies up to date
- Use secure random number generators
- Implement proper key management practices
- Consider security audits for production deployments

## Acknowledgments

We maintain a [Hall of Fame](https://bugbounty.bron.org/hall-of-fame) to recognize security researchers who help
improve the security of Bron's software.

---

**Thank you for helping keep Bron and the open source community safe!**
