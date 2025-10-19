package mina

import (
	"fmt"
	"math/big"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/hashing/poseidon"
)

type NetworkId string

const (
	// https://github.com/o1-labs/o1js-bindings/blob/df8c87ed6804465f79196fdff84e5147ae71e92d/crypto/constants.ts#L13
	TestNet NetworkId = "testnet"
	MainNet NetworkId = "mainnet"
)

var (
	testNetHashInput = new(big.Int).SetUint64(0x00)
	mainNetHashInput = new(big.Int).SetUint64(0x01)
)

type Prefix []byte

// https://github.com/o1-labs/o1js-bindings/blob/df8c87ed6804465f79196fdff84e5147ae71e92d/lib/binable.ts#L317
func (p Prefix) ToBaseFieldElement() (*pasta.PallasBaseFieldElement, error) {
	fieldSize := pasta.NewPallasBaseField().ElementSize() // TODO: ensure this is correct size
	if len(p) > fieldSize {
		return nil, errs.NewLength("prefix too long")
	}

	var feBytes [32]byte
	copy(feBytes[:], p)
	slices.Reverse(feBytes[:])
	out, err := pasta.NewPallasBaseField().FromBytes(feBytes[:])
	if err != nil {
		return nil, errs.WrapSerialisation(err, "set bytes failed")
	}
	return out, nil
}

// https://github.com/o1-labs/o1js/blob/885b50e60ead596cdcd8dc944df55fd3a4467a0a/src/mina-signer/src/signature.ts#L354
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

// https://github.com/o1-labs/o1js/blob/885b50e60ead596cdcd8dc944df55fd3a4467a0a/src/mina-signer/src/signature.ts#L354
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

// https://github.com/o1-labs/o1js/blob/fdc94dd8d3735d01c232d7d7af49763e044b738b/src/mina-signer/src/signature.ts#L305
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

// https://github.com/o1-labs/o1js/blob/fdc94dd8d3735d01c232d7d7af49763e044b738b/src/mina-signer/src/signature.ts#L292
// numberToBytePadded is equivalent to (b: number) => b.toString(2).padStart(8, '0')
func numberToBytePadded(b byte) string {
	return fmt.Sprintf("%08b", b)
}

// https://github.com/o1-labs/o1js/blob/fdc94dd8d3735d01c232d7d7af49763e044b738b/src/mina-signer/src/signature.ts#L294
// networkIdOfString replicates the JS logic exactly, returning (bigint, bitlength).
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

// https://github.com/o1-labs/o1js/blob/fdc94dd8d3735d01c232d7d7af49763e044b738b/src/bindings/lib/binable.ts#L315
func bytesToBits(bytes []byte) []bool {
	bits := make([]bool, 0, len(bytes)*8)
	for _, b := range bytes {
		for i := 0; i < 8; i++ {
			bits = append(bits, b&1 == 1)
			b >>= 1
		}
	}
	return bits
}

// https://github.com/o1-labs/o1js/blob/885b50e60ead596cdcd8dc944df55fd3a4467a0a/src/lib/provable/crypto/hash-generic.ts#L23
func hashWithPrefix(prefix Prefix, inputs ...*pasta.PallasBaseFieldElement) (*Scalar, error) {
	h := poseidon.NewLegacy()

	// salt
	pfe, err := prefix.ToBaseFieldElement()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not convert prefix to base field element")
	}
	h.Update(pfe)

	// hashWithPrefix itself
	h.Update(inputs...)

	digest := h.Digest()
	s, err := sf.FromBytes(digest.Bytes())
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot deserialize scalar")
	}

	return s, nil
}
