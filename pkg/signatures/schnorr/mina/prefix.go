package mina

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type NetworkId string

var (
	// https://github.com/o1-labs/o1js-bindings/blob/df8c87ed6804465f79196fdff84e5147ae71e92d/crypto/constants.ts#L13
	TestNet NetworkId = "testnet"
	MainNet NetworkId = "mainnet"
)

type Prefix []byte

// https://github.com/o1-labs/o1js-bindings/blob/df8c87ed6804465f79196fdff84e5147ae71e92d/lib/binable.ts#L317
func (p Prefix) ToBaseFieldElement() (curves.BaseFieldElement, error) {
	fieldSize := pasta.NewPallasBaseField().ElementSize() // TODO: ensure this is correct size
	if len(p) > fieldSize {
		return nil, errs.NewLength("prefix too long")
	}

	var feBytes [32]byte
	copy(feBytes[:], p)
	slices.Reverse(feBytes[:])
	out, err := pasta.NewPallasBaseField().Element().SetBytes(feBytes[:])
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
