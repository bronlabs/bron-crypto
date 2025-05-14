package dkls23

import (
	"bytes"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curveutils"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures"
)

type (
	SigningKeyShare = tsignatures.SigningKeyShare
	PublicKeyShares = tsignatures.PartialPublicKeys
	PairwiseSeeds   = rprzs.PairWiseSeeds
)

type PartialSignature struct {
	Ui curves.Scalar
	Wi curves.Scalar
	Ri curves.Point

	_ ds.Incomparable
}

func (ps *PartialSignature) Validate(protocol types.ThresholdSignatureProtocol) error {
	if ps.Ui == nil {
		return errs.NewIsNil("Ui")
	}
	if ps.Wi == nil {
		return errs.NewIsNil("Wi")
	}
	if ps.Ri == nil {
		return errs.NewIsNil("Ri")
	}
	if !curveutils.AllScalarsOfSameCurve(protocol.Curve(), ps.Ui, ps.Wi) {
		return errs.NewCurve("Ui and Wi have different curves")
	}
	if !curveutils.AllPointsOfSameCurve(protocol.Curve(), ps.Ri) {
		return errs.NewCurve("Ri has different curve")
	}
	if ps.Ui.IsZero() {
		return errs.NewIsZero("Ui is zero")
	}
	if ps.Wi.IsZero() {
		return errs.NewIsZero("Wi is zero")
	}
	if ps.Ri.IsAdditiveIdentity() {
		return errs.NewIsZero("Ri is identity")
	}
	return nil
}

var (
	_ tsignatures.Shard = (*Shard)(nil)
	_ tsignatures.Shard = (*DerivedShard)(nil)
)

type Shard struct {
	SigningKeyShare *SigningKeyShare
	PublicKeyShares *PublicKeyShares

	_ ds.Incomparable
}

func NewShard(protocol types.ThresholdProtocol, signingKeyShare *SigningKeyShare, partialPublicKeys *PublicKeyShares) (*Shard, error) {
	if err := signingKeyShare.Validate(protocol); err != nil {
		return nil, errs.WrapVerification(err, "invalid signing key share")
	}
	if err := partialPublicKeys.Validate(protocol); err != nil {
		return nil, errs.WrapVerification(err, "invalid public key share")
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
	if s == nil {
		return errs.NewIsNil("receiver")
	}
	if err := s.SigningKeyShare.Validate(protocol); err != nil {
		return errs.WrapVerification(err, "invalid signing key share")
	}
	if err := s.PublicKeyShares.Validate(protocol); err != nil {
		return errs.WrapVerification(err, "invalid public key shares")
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

func (s *Shard) Derive(chainCode [32]byte, i uint32) (*DerivedShard, error) {
	shift, childChainCode, err := tsignatures.PublicChildKeyDerivation(s.PublicKey(), chainCode, i)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive")
	}

	derivedShard := &DerivedShard{
		Shard: &Shard{
			SigningKeyShare: s.SigningKeyShare.Shift(shift),
			PublicKeyShares: s.PublicKeyShares.Shift(shift),
		},
		ChainCode: childChainCode,
	}

	return derivedShard, nil
}

type DerivedShard struct {
	Shard     *Shard
	ChainCode [32]byte
}

func (s *DerivedShard) Equal(other tsignatures.Shard) bool {
	otherShard, ok := other.(*DerivedShard)
	return ok && s.Shard.Equal(otherShard.Shard) && bytes.Equal(s.ChainCode[:], otherShard.ChainCode[:])
}

func (s *DerivedShard) Validate(protocol types.ThresholdProtocol) error {
	if s == nil {
		return errs.NewIsNil("receiver")
	}
	if err := s.Shard.Validate(protocol); err != nil {
		return errs.WrapVerification(err, "invalid signing key share")
	}

	return nil
}

func (s *DerivedShard) SecretShare() curves.Scalar {
	return s.Shard.SigningKeyShare.Share
}

func (s *DerivedShard) PublicKey() curves.Point {
	return s.Shard.SigningKeyShare.PublicKey
}

func (s *DerivedShard) PartialPublicKeys() ds.Map[types.SharingID, curves.Point] {
	return s.Shard.PublicKeyShares.Shares
}

func (s *DerivedShard) FeldmanCommitmentVector() []curves.Point {
	return s.Shard.PublicKeyShares.FeldmanCommitmentVector
}

func (s *DerivedShard) Derive(i uint32) (*DerivedShard, error) {
	derivedShard, err := s.Shard.Derive(s.ChainCode, i)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot derive")
	}

	return derivedShard, nil
}

func (s *DerivedShard) AsShard() *Shard {
	return s.Shard
}

type PreProcessingMaterial tsignatures.PreProcessingMaterial[*PrivatePreProcessingMaterial, PreSignature]

func (ppm *PreProcessingMaterial) Validate(myIdentityKey types.IdentityKey, protocol types.ThresholdSignatureProtocol) error {
	if ppm == nil {
		return errs.NewIsNil("receiver")
	}
	if ppm.PreSigners == nil {
		return errs.NewIsNil("presigners")
	}
	if ppm.PreSigners.Size() < int(protocol.Threshold()) {
		return errs.NewSize("not enough session participants: %d", ppm.PreSigners.Size())
	}
	if !ppm.PreSigners.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("presigners must be non empty subset of all participants")
	}
	if ppm.PrivateMaterial == nil {
		return errs.NewIsNil("private material")
	}
	if err := ppm.PrivateMaterial.Validate(myIdentityKey, protocol, ppm.PreSigners); err != nil {
		return errs.WrapValidation(err, "private material")
	}
	if ppm.PreSignature == nil {
		return errs.NewIsNil("public material")
	}
	for participant := range ppm.PreSigners.Iter() {
		Ri, exists := ppm.PreSignature.Get(participant)
		if !exists {
			return errs.NewMissing("could not find Ri for identity %s", participant.String())
		}
		if Ri == nil {
			return errs.NewIsNil("Ri")
		}
		if participant.Equal(myIdentityKey) && !Ri.Equal(protocol.Curve().ScalarBaseMult(ppm.PrivateMaterial.R)) {
			return errs.NewValue("my R contribution")
		}
	}
	return nil
}

type PrivatePreProcessingMaterial struct {
	R    curves.Scalar
	Phi  curves.Scalar
	Zeta curves.Scalar
	Cu   map[types.SharingID]curves.Scalar
	Cv   map[types.SharingID]curves.Scalar
	Du   map[types.SharingID]curves.Scalar
	Dv   map[types.SharingID]curves.Scalar
	Psi  map[types.SharingID]curves.Scalar
	_    ds.Incomparable
}

func (pppm *PrivatePreProcessingMaterial) Validate(myIdentityKey types.IdentityKey, protocol types.ThresholdSignatureProtocol, preSigners ds.Set[types.IdentityKey]) error {
	if pppm == nil {
		return errs.NewIsNil("receiver")
	}
	if pppm.R == nil {
		return errs.NewIsNil("R")
	}
	if pppm.Phi == nil {
		return errs.NewIsNil("Phi")
	}
	if pppm.Zeta == nil {
		return errs.NewIsNil("Zeta")
	}
	sharingConfig := types.DeriveSharingConfig(preSigners)
	for participant := range preSigners.Iter() {
		if participant.Equal(myIdentityKey) {
			continue
		}
		id, exists := sharingConfig.Reverse().Get(participant)
		if !exists {
			return errs.NewMissing("could not find sharing id of %s", participant.String())
		}
		cu, exists := pppm.Cu[id]
		if !exists {
			return errs.NewMissing("cu for id=%d", id)
		}
		if cu == nil {
			return errs.NewIsNil("cu")
		}
		cv, exists := pppm.Cv[id]
		if !exists {
			return errs.NewMissing("cv for id=%d", id)
		}
		if cv == nil {
			return errs.NewIsNil("cv")
		}
		du, exists := pppm.Du[id]
		if !exists {
			return errs.NewMissing("du for id=%d", id)
		}
		if du == nil {
			return errs.NewIsNil("du")
		}
		dv, exists := pppm.Dv[id]
		if !exists {
			return errs.NewMissing("dv for id=%d", id)
		}
		if dv == nil {
			return errs.NewIsNil("dv")
		}
		psi, exists := pppm.Psi[id]
		if !exists {
			return errs.NewMissing("psi for id=%d", id)
		}
		if psi == nil {
			return errs.NewIsNil("psi")
		}
	}
	if !curveutils.AllIdentityKeysWithSameCurve(myIdentityKey.PublicKey().Curve(), protocol.Participants().List()...) {
		return errs.NewCurve("myIdentityKey and participants have different curves")
	}
	if !curveutils.AllIdentityKeysWithSameCurve(myIdentityKey.PublicKey().Curve(), preSigners.List()...) {
		return errs.NewCurve("myIdentityKey and preSigners have different curves")
	}
	return nil
}

// PreSignature is individual contributions to R.
type PreSignature ds.Map[types.IdentityKey, curves.Point]
