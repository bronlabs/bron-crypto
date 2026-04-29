// Package base58 implements Bitcoin-flavor Base58 and Base58Check
// encoding for binary data such as version-tagged addresses and key
// material.
//
// Base58 is an encoding, not a cryptographic primitive. Plain
// [Encode]/[Decode] provide neither confidentiality nor integrity.
// [CheckEncode]/[CheckDecode] add a 4-byte truncated double-SHA-256
// checksum that detects accidental corruption but does not authenticate:
// the checksum is unkeyed, so an adversary who controls the input can
// always produce a string that decodes successfully.
//
// See README.md for the alphabet, encoding rules, the Base58Check
// construction, and timing-sensitivity caveats.
package base58
