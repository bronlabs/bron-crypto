package lindell22

import (
	"bytes"

	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures"
)

var (
	_ tsignatures.Shard = (*Shard)(nil)
	_ tsignatures.Shard = (*ExtendedShard)(nil)
)

type Shard struct {
	SigningKeyShare *tsignatures.SigningKeyShare
	PublicKeyShares *tsignatures.PartialPublicKeys

	_ ds.Incomparable
}

func NewShard(protocol types.ThresholdProtocol, signingKeyShare *tsignatures.SigningKeyShare, partialPublicKeys *tsignatures.PartialPublicKeys) (*Shard, error) {
	if err := signingKeyShare.Validate(protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid signing key share")
	}
	if err := partialPublicKeys.Validate(protocol); err != nil {
		return nil, errs.WrapValidation(err, "invalid public key share")
	}

	shard := &Shard{
		SigningKeyShare: signingKeyShare,
		PublicKeyShares: partialPublicKeys,
	}

	return shard, nil
}

func (s *Shard) Equal(other tsignatures.Shard) bool {
	otherShard, ok := other.(*Shard)
	return ok && s.SigningKeyShare.Equal(otherShard.SigningKeyShare) && s.PublicKeyShares.Equal(otherShard.PublicKeyShares)
}

func (s *Shard) Validate(protocol types.ThresholdProtocol) error {
	if err := s.SigningKeyShare.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "invalid signing key share")
	}
	if err := s.PublicKeyShares.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "invalid public key shares map")
	}
	return nil
}

func (s *Shard) SecretShare() curves.Scalar {
	return s.SigningKeyShare.Share
}

func (s *Shard) PublicKey() curves.Point {
	return s.SigningKeyShare.PublicKey
}

func (s *Shard) PartialPublicKeys() ds.Map[types.SharingID, curves.Point] {
	return s.PublicKeyShares.Shares
}

func (s *Shard) FeldmanCommitmentVector() []curves.Point {
	return s.PublicKeyShares.FeldmanCommitmentVector
}

func (s *Shard) ChainCode() []byte {
	feldmanVectorBytes := sliceutils.Map(s.FeldmanCommitmentVector(), curves.Point.ToAffineCompressed)
	chainCode, _ := hashing.HmacPrefixedLength([]byte("ChainCode"), sha3.New256, feldmanVectorBytes...)
	return chainCode
}

func (s *Shard) Derive(i uint32) (*ExtendedShard, error) {
	chainCode := s.ChainCode()
	return s.DeriveWithChainCode(chainCode, i)
}

func (s *Shard) DeriveWithChainCode(chainCode []byte, i uint32) (*ExtendedShard, error) {
	shift, childChainCode, err := tsignatures.ChildKeyDerivation(s.PublicKey(), chainCode, i)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive child")
	}
	childSigningKeyShare := s.SigningKeyShare.Shift(shift)
	childPublicKeyShares := s.PublicKeyShares.Shift(shift)
	if childPublicKeyShares.PublicKey.IsAdditiveIdentity() {
		return nil, errs.NewIsIdentity("cannot derive child")
	}

	derivedShard := &ExtendedShard{
		Shard: &Shard{
			SigningKeyShare: childSigningKeyShare,
			PublicKeyShares: childPublicKeyShares,
		},
		ChainCodeBytes: childChainCode,
	}
	return derivedShard, nil
}

type ExtendedShard struct {
	Shard          *Shard
	ChainCodeBytes []byte
}

func (s *ExtendedShard) SecretShare() curves.Scalar {
	return s.Shard.SecretShare()
}

func (s *ExtendedShard) PublicKey() curves.Point {
	return s.Shard.PublicKey()
}

func (s *ExtendedShard) PartialPublicKeys() ds.Map[types.SharingID, curves.Point] {
	return s.Shard.PartialPublicKeys()
}

func (s *ExtendedShard) FeldmanCommitmentVector() []curves.Point {
	return s.Shard.FeldmanCommitmentVector()
}

func (s *ExtendedShard) Equal(rhs tsignatures.Shard) bool {
	other, ok := rhs.(*ExtendedShard)
	if !ok {
		return false
	}
	if s == nil || other == nil {
		return s == other
	}
	return s.Shard.Equal(other.Shard) && bytes.Equal(s.ChainCodeBytes, other.ChainCodeBytes)
}

func (s *ExtendedShard) Derive(i uint32) (*ExtendedShard, error) {
	derivedShard, err := s.Shard.DeriveWithChainCode(s.ChainCodeBytes, i)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive child")
	}
	return derivedShard, nil
}

func (s *ExtendedShard) AsShard() *Shard {
	return s.Shard
}

func (s *ExtendedShard) ChainCode() []byte {
	return s.ChainCodeBytes
}
