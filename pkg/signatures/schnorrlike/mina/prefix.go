package mina

import (
	"fmt"
	"math/big"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/hashing/poseidon"
)

// NetworkId identifies a Mina network for domain separation in signatures.
// Different networks use different prefixes to prevent signature replay attacks
// across networks.
type NetworkId string

const (
	// TestNet is the Mina test network, using the legacy "CodaSignature" prefix.
	// Reference: https://github.com/o1-labs/o1js-bindings/blob/df8c87ed6804465f79196fdff84e5147ae71e92d/crypto/constants.ts#L13
	TestNet NetworkId = "testnet"
	// MainNet is the Mina main network, using the "MinaSignatureMainnet" prefix.
	MainNet NetworkId = "mainnet"
)

var (
	// testNetHashInput is the network ID byte for TestNet (0x00) used in nonce derivation.
	testNetHashInput = new(big.Int).SetUint64(0x00)
	// mainNetHashInput is the network ID byte for MainNet (0x01) used in nonce derivation.
	mainNetHashInput = new(big.Int).SetUint64(0x01)
)

// Prefix is a domain separation string used in Mina's signature hashing.
// It is converted to a field element and included in the Poseidon hash input.
type Prefix []byte

// ToBaseFieldElement converts the prefix to a Pallas base field element.
// The prefix bytes are interpreted as a little-endian integer and converted
// to a field element for use in Poseidon hashing.
//
// Reference: https://github.com/o1-labs/o1js-bindings/blob/df8c87ed6804465f79196fdff84e5147ae71e92d/lib/binable.ts#L317
func (p Prefix) ToBaseFieldElement() (*pasta.PallasBaseFieldElement, error) {
	fieldSize := pasta.NewPallasBaseField().ElementSize() // TODO: ensure this is correct size
	if len(p) > fieldSize {
		return nil, ErrSerialization.WithMessage("prefix too long")
	}

	var feBytes [32]byte
	copy(feBytes[:], p)
	slices.Reverse(feBytes[:])
	out, err := pasta.NewPallasBaseField().FromBytes(feBytes[:])
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("set bytes failed")
	}
	return out, nil
}

// SignaturePrefix returns the domain separation prefix for signatures on the given network.
// MainNet uses "MinaSignatureMainnet" and TestNet uses "CodaSignature*******" (legacy).
// Custom network IDs generate a prefix by padding/truncating to exactly 20 characters.
//
// Reference: https://github.com/o1-labs/o1js/blob/885b50e60ead596cdcd8dc944df55fd3a4467a0a/src/mina-signer/src/signature.ts#L354
func SignaturePrefix(nid NetworkId) Prefix {
	switch nid {
	case MainNet:
		return []byte("MinaSignatureMainnet")
	case TestNet:
		return []byte("CodaSignature*******")
	default:
		return createCustomPrefix(string(nid) + ("Signature"))
	}
}

// createCustomPrefix creates a 20-character prefix from a custom network ID string.
// If the input is shorter than 20 characters, it is padded with '*' characters.
// If longer, it is truncated to 20 characters.
//
// Reference: https://github.com/o1-labs/o1js/blob/885b50e60ead596cdcd8dc944df55fd3a4467a0a/src/mina-signer/src/signature.ts#L354
func createCustomPrefix(input string) Prefix {
	maxLength := 20
	paddingChar := '*'
	length := len(input)
	if length <= maxLength {
		diff := maxLength - length
		padding := make([]byte, diff)
		for i := range diff {
			padding[i] = byte(paddingChar)
		}
		return slices.Concat([]byte(input), padding)
	} else {
		return []byte(input[:maxLength])
	}
}

// getNetworkIdHashInput returns the network ID as a big.Int and its bit length
// for inclusion in the nonce derivation hash. MainNet is 0x01 (8 bits),
// TestNet is 0x00 (8 bits), and custom networks encode the string as bits.
//
// Reference: https://github.com/o1-labs/o1js/blob/fdc94dd8d3735d01c232d7d7af49763e044b738b/src/mina-signer/src/signature.ts#L305
func getNetworkIdHashInput(nid NetworkId) (*big.Int, int) {
	switch nid {
	case MainNet:
		return mainNetHashInput, 8
	case TestNet:
		return testNetHashInput, 8
	default:
		return networkIdOfString(string(nid))
	}
}

// numberToBytePadded formats a byte as an 8-character binary string, zero-padded.
// Equivalent to JS: (b: number) => b.toString(2).padStart(8, '0')
//
// Reference: https://github.com/o1-labs/o1js/blob/fdc94dd8d3735d01c232d7d7af49763e044b738b/src/mina-signer/src/signature.ts#L292
func numberToBytePadded(b byte) string {
	return fmt.Sprintf("%08b", b)
}

// networkIdOfString converts a custom network ID string to a big.Int and bit length.
// The string is encoded as reversed binary digits (each character as 8-bit MSB-first),
// then interpreted as an integer. Returns the value and total bit count.
//
// Reference: https://github.com/o1-labs/o1js/blob/fdc94dd8d3735d01c232d7d7af49763e044b738b/src/mina-signer/src/signature.ts#L294
func networkIdOfString(n string) (*big.Int, int) {
	acc := ""
	for i := len(n) - 1; i >= 0; i-- {
		b := n[i]
		padded := numberToBytePadded(b)
		acc += padded
	}
	val := new(big.Int)
	val.SetString(acc, 2)
	return val, len(acc)
}

// bytesToBits converts a byte slice to a bit slice in LSB-first order per byte.
// Each byte is expanded to 8 bits, with the least significant bit first.
// This matches the o1js binable encoding.
//
// Reference: https://github.com/o1-labs/o1js/blob/fdc94dd8d3735d01c232d7d7af49763e044b738b/src/bindings/lib/binable.ts#L315
func bytesToBits(bytes []byte) []bool {
	bits := make([]bool, 0, len(bytes)*8)
	for _, b := range bytes {
		for range 8 {
			bits = append(bits, b&1 == 1)
			b >>= 1
		}
	}
	return bits
}

// reversedBytes returns a new byte slice with elements in reversed order.
// Used to convert between big-endian and little-endian byte representations.
func reversedBytes(b []byte) []byte {
	result := make([]byte, len(b))
	for i := range b {
		result[i] = b[len(b)-1-i]
	}
	return result
}

// hashWithPrefix computes a Poseidon hash with domain separation.
// The prefix is converted to a field element and prepended to the inputs,
// then hashed using Poseidon Legacy. The result is returned as a scalar
// for use as a Fiat-Shamir challenge in signature computation.
//
// Reference: https://github.com/o1-labs/o1js/blob/885b50e60ead596cdcd8dc944df55fd3a4467a0a/src/lib/provable/crypto/hash-generic.ts#L23
func hashWithPrefix(prefix Prefix, inputs ...*pasta.PallasBaseFieldElement) (*Scalar, error) {
	h := poseidon.NewLegacy()

	// salt
	pfe, err := prefix.ToBaseFieldElement()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("could not convert prefix to base field element")
	}
	h.Update(pfe)

	// hashWithPrefix itself
	h.Update(inputs...)

	digest := h.Digest()
	s, err := sf.FromBytes(digest.Bytes())
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot deserialize scalar")
	}

	return s, nil
}
