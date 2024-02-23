package dkls24

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/ct"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

type (
	SigningKeyShare = tsignatures.SigningKeyShare
	PublicKeyShares = tsignatures.PartialPublicKeys
	PairwiseSeeds   = przs.PairWiseSeeds
)

type PartialSignature struct {
	Ui curves.Scalar
	Wi curves.Scalar
	Ri curves.Point

	_ ds.Incomparable
}

type BaseOTConfig struct {
	AsSender   *ot.SenderRotOutput
	AsReceiver *ot.ReceiverRotOutput

	_ ds.Incomparable
}

func (b *BaseOTConfig) Validate() error {
	if b.AsSender == nil || len(b.AsSender.Messages) == 0 {
		return errs.NewArgument("invalid base OT as sender")
	}
	if b.AsReceiver == nil || len(b.AsReceiver.ChosenMessages) == 0 || len(b.AsReceiver.Choices) == 0 {
		return errs.NewArgument("invalid base OT as receiver")
	}
	return nil
}

var _ tsignatures.Shard = (*Shard)(nil)

type Shard struct {
	SigningKeyShare *SigningKeyShare
	PublicKeyShares *PublicKeyShares
	PairwiseSeeds   PairwiseSeeds
	PairwiseBaseOTs ds.Map[types.IdentityKey, *BaseOTConfig]

	_ ds.Incomparable
}

func (s *Shard) Validate(protocol types.ThresholdProtocol, holderIdentityKey types.IdentityKey) error {
	if s == nil {
		return errs.NewIsNil("receiver")
	}
	if err := s.SigningKeyShare.Validate(protocol); err != nil {
		return errs.WrapVerification(err, "invalid signing key share")
	}
	if err := s.PublicKeyShares.Validate(protocol); err != nil {
		return errs.WrapVerification(err, "invalid public key shares")
	}
	if s.PairwiseBaseOTs == nil {
		return errs.NewIsNil("pairwise base ot")
	}
	pairwiseBaseOTHolders := hashset.NewHashableHashSet(s.PairwiseBaseOTs.Keys()...)
	if delta := pairwiseBaseOTHolders.SymmetricDifference(protocol.Participants()); delta.Size() != 1 || !delta.Contains(holderIdentityKey) {
		return errs.NewMembership("pairwise base ot")
	}
	for pair := range s.PairwiseBaseOTs.Iter() {
		id := pair.Key
		v := pair.Value
		if v == nil {
			return errs.NewIsNil("base ot pair for id %x", id.PublicKey())
		}
		if v.AsSender == nil {
			return errs.NewIsNil("base ot as sender wrt id %x", id.PublicKey())
		}
		if v.AsReceiver == nil {
			return errs.NewIsNil("base ot as receiver wrt id %x", id.PublicKey())
		}
	}
	if s.PairwiseSeeds == nil {
		return errs.NewIsNil("pairwise seeds")
	}
	pairwiseSeedHolders := hashset.NewHashableHashSet(s.PairwiseSeeds.Keys()...)
	if delta := pairwiseSeedHolders.SymmetricDifference(protocol.Participants()); delta.Size() != 1 || !delta.Contains(holderIdentityKey) {
		return errs.NewMembership("pairwise seed holders")
	}
	for _, seed := range s.PairwiseSeeds.Values() {
		if ct.IsAllZero(seed[:]) == 1 {
			return errs.NewIsZero("found a zero przs seed")
		}
	}
	return nil
}

func (s *Shard) SecretShare() curves.Scalar {
	return s.SigningKeyShare.Share
}

func (s *Shard) PublicKey() curves.Point {
	return s.SigningKeyShare.PublicKey
}

func (s *Shard) PartialPublicKeys() ds.Map[types.IdentityKey, curves.Point] {
	return s.PublicKeyShares.Shares
}

func (s *Shard) FeldmanCommitmentVector() []curves.Point {
	return s.PublicKeyShares.FeldmanCommitmentVector
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
			return errs.NewMissing("could not find Ri for identity %x", participant.PublicKey())
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
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	for participant := range preSigners.Iter() {
		if participant.Equal(myIdentityKey) {
			continue
		}
		id, exists := sharingConfig.Reverse().Get(participant)
		if !exists {
			return errs.NewMissing("could not find sharing id of %x", participant.PublicKey())
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
	return nil
}

// PreSignature is individual contributions to R.
type PreSignature ds.Map[types.IdentityKey, curves.Point]
