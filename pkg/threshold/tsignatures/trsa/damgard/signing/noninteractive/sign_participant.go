package noninteractive

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/rsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/damgard"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/damgard/signing"
)

type Cosigner struct {
	protocol types.ThresholdSignatureProtocol
	padding  rsa.Padding

	myIdentityKey types.IdentityKey
	mySharingId   types.SharingID
	myShard       *damgard.Shard
}

func (c *Cosigner) IdentityKey() types.IdentityKey {
	return c.myIdentityKey
}

func (c *Cosigner) SharingId() types.SharingID {
	return c.mySharingId
}

var _ types.ThresholdSignatureParticipant = (*Cosigner)(nil)

func NewCosigner(protocol types.ThresholdSignatureProtocol, padding rsa.Padding, myIdentityKey types.IdentityKey, myShard *damgard.Shard) (*Cosigner, error) {
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, ok := sharingConfig.Reverse().Get(myIdentityKey)
	if !ok {
		return nil, errs.NewFailed("invalid identity key")
	}

	return &Cosigner{
		protocol:      protocol,
		padding:       padding,
		myIdentityKey: myIdentityKey,
		mySharingId:   mySharingId,
		myShard:       myShard,
	}, nil
}

func (c *Cosigner) ProducePartialSignature(message []byte) (*signing.RsaPartialSignature, error) {
	delta := int64(1)
	for i := int64(2); i <= int64(c.protocol.TotalParties()); i++ {
		delta *= i
	}
	base := delta * delta * 2
	baseNat := new(saferith.Nat).SetUint64(uint64(base))
	exponent := new(saferith.Nat).Mul(baseNat, c.myShard.Di, -1)

	digestPaddedNat, err := c.padding.HashAndPad(c.myShard.N.BitLen(), c.protocol.SigningSuite().Hash(), message)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot pad message")
	}

	partSignature := new(saferith.Nat).Exp(digestPaddedNat, exponent, c.myShard.N)

	return &signing.RsaPartialSignature{
		Share: partSignature,
	}, nil
}
