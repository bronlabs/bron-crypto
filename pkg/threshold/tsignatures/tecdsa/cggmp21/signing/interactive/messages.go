package interactive_signing

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa/paillier"
	"github.com/bronlabs/krypton-primitives/pkg/network"
)

var (
	_ network.Message[types.ThresholdSignatureProtocol] = (*Round1Broadcast)(nil)
	_ network.Message[types.ThresholdSignatureProtocol] = (*Round2Broadcast)(nil)
	_ network.Message[types.ThresholdSignatureProtocol] = (*Round2P2P)(nil)
	_ network.Message[types.ThresholdSignatureProtocol] = (*Round3Broadcast)(nil)
)

type Round1Broadcast struct {
	BigK *paillier.CipherText
	BigG *paillier.CipherText
}

type Round2Broadcast struct {
	BigGamma curves.Point
}

type Round2P2P struct {
	BigD     *paillier.CipherText
	BigDDash *paillier.CipherText
	BigF     *paillier.CipherText
	BigFDash *paillier.CipherText
}

type Round3Broadcast struct {
	Delta    curves.Scalar
	BigDelta curves.Point
	BigS     curves.Point
}

func (m *Round1Broadcast) Validate(protocol types.ThresholdSignatureProtocol) error {
	return nil
}

func (m *Round2Broadcast) Validate(protocol types.ThresholdSignatureProtocol) error {
	return nil
}

func (m *Round2P2P) Validate(protocol types.ThresholdSignatureProtocol) error {
	return nil
}

func (m *Round3Broadcast) Validate(protocol types.ThresholdSignatureProtocol) error {
	return nil
}
