package noninteractive_signing

import (
	"slices"
	"sort"

	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curveutils"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
)

type PrivateNoncePair struct {
	SmallD curves.Scalar
	SmallE curves.Scalar

	_ ds.Incomparable
}

type AttestedCommitmentToNoncePair struct {
	Attestor    types.IdentityKey
	D           curves.Point
	E           curves.Point
	Attestation []byte

	_ ds.Incomparable
}

func (ac *AttestedCommitmentToNoncePair) Equal(rhs *AttestedCommitmentToNoncePair) bool {
	return ac.Attestor.PublicKey().Equal(rhs.Attestor.PublicKey()) &&
		ac.D.Equal(rhs.D) &&
		ac.E.Equal(rhs.E) &&
		slices.Equal(ac.Attestation, rhs.Attestation)
}

func (ac *AttestedCommitmentToNoncePair) Validate(protocol types.ThresholdProtocol) error {
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapArgument(err, "protocol config is invalid")
	}
	if ac == nil {
		return errs.NewIsNil("attested commitment to nonce is nil")
	}
	if ac.Attestor == nil {
		return errs.NewIsNil("attestor is nil")
	}
	if !protocol.Participants().Contains(ac.Attestor) {
		return errs.NewArgument("attestor is not in protocol config")
	}
	if ac.D.IsAdditiveIdentity() {
		return errs.NewIsIdentity("D is at infinity")
	}
	if ac.E.IsAdditiveIdentity() {
		return errs.NewIsIdentity("E is at infinity")
	}
	dCurve := ac.D.Curve()
	eCurve := ac.E.Curve()

	if dCurve.Name() != eCurve.Name() {
		return errs.NewCurve("D and E are not on the same curve %s != %s", dCurve.Name(), eCurve.Name())
	}
	message := ac.D.ToAffineCompressed()
	message = append(message, ac.E.ToAffineCompressed()...)
	if err := ac.Attestor.Verify(ac.Attestation, message); err != nil {
		return errs.WrapVerification(err, "could not verify attestation")
	}
	if !curveutils.AllOfSameCurve(protocol.Curve(), ac.D, ac.E) {
		return errs.NewCurve("curve mismatch")
	}
	return nil
}

type PreSignature []*AttestedCommitmentToNoncePair

func (ps *PreSignature) Validate(protocol types.ThresholdProtocol) error {
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapArgument(err, "protocol config config is invalid")
	}
	if ps == nil {
		return errs.NewIsNil("presignature is nil")
	}
	DHashSet := map[curves.Point]bool{}
	EHashSet := map[curves.Point]bool{}
	for _, thisPartyAttestedCommitment := range *ps {
		if DHashSet[thisPartyAttestedCommitment.D] {
			return errs.NewMembership("found duplicate D")
		}
		if EHashSet[thisPartyAttestedCommitment.E] {
			return errs.NewMembership("found duplicate E")
		}
		if err := thisPartyAttestedCommitment.Validate(protocol); err != nil {
			return errs.WrapValidation(err, "invalid attested commitments")
		}
		DHashSet[thisPartyAttestedCommitment.D] = true
		EHashSet[thisPartyAttestedCommitment.E] = true
	}
	if err := sortPreSignatureInPlace(protocol, *ps); err != nil {
		return errs.WrapFailed(err, "could not sort presignature")
	}
	return nil
}

func (ps *PreSignature) Ds() []curves.Point {
	result := make([]curves.Point, len(*ps))
	for i := 0; i < len(*ps); i++ {
		result[i] = (*ps)[i].D
	}
	return result
}

func (ps *PreSignature) Es() []curves.Point {
	result := make([]curves.Point, len(*ps))
	for i := 0; i < len(*ps); i++ {
		result[i] = (*ps)[i].E
	}
	return result
}

type PreSignatureBatch []PreSignature

func (psb *PreSignatureBatch) Validate(protocol types.ThresholdProtocol) error {
	if psb == nil {
		return errs.NewIsNil("presignature is nil")
	}
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "could not validate protocol config")
	}
	if len(*psb) == 0 {
		return errs.NewIsZero("batch is empty")
	}

	// checking for duplicates across all presignatures.
	DHashSet := map[curves.Point]bool{}
	EHashSet := map[curves.Point]bool{}
	for i, preSignature := range *psb {
		if err := preSignature.Validate(protocol); err != nil {
			return errs.WrapValidation(err, "presignature with index %d is invalid", i)
		}
		for _, D := range preSignature.Ds() {
			if DHashSet[D] {
				return errs.NewMembership("found duplicate D")
			}
			DHashSet[D] = true
		}
		for _, E := range preSignature.Es() {
			if EHashSet[E] {
				return errs.NewMembership("found duplicate E")
			}
			EHashSet[E] = true
		}
	}
	return nil
}

// We require that attested commitments within a presignature are sorted by the sharing id of the attestor.
func sortPreSignatureInPlace(protocol types.ThresholdProtocol, attestedCommitments []*AttestedCommitmentToNoncePair) error {
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapArgument(err, "protocol config is invalid")
	}
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	sort.Slice(attestedCommitments, func(i, j int) bool {
		si, _ := sharingConfig.Reverse().Get(attestedCommitments[i].Attestor)
		sj, _ := sharingConfig.Reverse().Get(attestedCommitments[j].Attestor)
		return si < sj
	})
	return nil
}
