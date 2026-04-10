package redistribute

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
)

// Round1Broadcast carries the public commitments
// that let previous shareholders verify the redistributed subshares.
type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	// ShareVerificationVector authenticates the previous shareholder's share.
	ShareVerificationVector *feldman.VerificationVector[G, S]
	// SubShareVerificationVector authenticates the previous shareholder's redistributed
	// contribution under the next access structure.
	SubShareVerificationVector *feldman.VerificationVector[G, S]
}

// Validate checks that the broadcast contains well-formed verification data.
func (m *Round1Broadcast[G, S]) Validate(p *Participant[G, S], _ sharing.ID) error {
	if m == nil || m.ShareVerificationVector == nil || m.SubShareVerificationVector == nil {
		return ErrValidation.WithMessage("invalid arguments")
	}
	if !m.ShareVerificationVector.Value().IsColumnVector() {
		return ErrValidation.WithMessage("invalid share verification vector")
	}
	if !m.SubShareVerificationVector.Value().IsColumnVector() {
		return ErrValidation.WithMessage("invalid sub-share verification vector")
	}
	if p.prevShard != nil {
		if r, _ := m.ShareVerificationVector.Value().Dimensions(); r != int(p.prevShard.MSP().D()) {
			return ErrValidation.WithMessage("invalid share verification vector dimensions")
		}
	}
	basePoint, err := m.SubShareVerificationVector.Value().Get(0, 0)
	if err != nil {
		return ErrValidation.WithMessage("invalid sub-share verification vector")
	}
	nextMSP, err := accessstructures.InducedMSP(
		algebra.StructureMustBeAs[algebra.PrimeField[S]](
			algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](basePoint.Structure()).ScalarStructure(),
		),
		p.nextAccessStructures,
	)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot induce MSP for next access structure")
	}
	if r, _ := m.SubShareVerificationVector.Value().Dimensions(); r != int(nextMSP.D()) {
		return ErrValidation.WithMessage("invalid sub-share verification vector dimensions")
	}

	return nil
}

// Round1P2P carries one previous shareholder's private subshare for a specific next shareholder.
type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	// SubShare is the previous shareholder's private contribution to the recipient's new share.
	SubShare *kw.Share[S]
}

// Validate checks that the private redistribution message is well-formed.
func (m *Round1P2P[G, S]) Validate(p *Participant[G, S], _ sharing.ID) error {
	if m == nil || m.SubShare == nil {
		return ErrValidation.WithMessage("invalid arguments")
	}
	if p.ctx.HolderID() != m.SubShare.ID() {
		return ErrValidation.WithMessage("invalid sub-share ID")
	}

	return nil
}
