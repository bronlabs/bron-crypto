package redistribute

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/hjky"
)

// Round1Broadcast carries the public HJKY round-1 broadcast that previous
// shareholders send to all parties.
type Round1Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	// ZeroR1 is the sender's broadcast from round 1 of the HJKY zero-sharing
	// subprotocol run among the previous shareholders.
	ZeroR1 *hjky.Round1Broadcast[G, S]
}

// Validate checks that the broadcast contains a well-formed HJKY round-1
// message when the sender is a previous shareholder.
func (m *Round1Broadcast[G, S]) Validate(p *Participant[G, S], fromID sharing.ID) error {
	if p.isPrevShareholder(fromID) && p.zeroParticipant != nil {
		if m == nil || m.ZeroR1 == nil {
			return ErrValidation.WithMessage("no message")
		}
		if err := m.ZeroR1.Validate(p.zeroParticipant, fromID); err != nil {
			return errs.Wrap(err).WithMessage("invalid message")
		}
	}

	return nil
}

// Round1P2P carries one previous shareholder's private HJKY round-1 message
// for another previous shareholder.
type Round1P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	// ZeroR1 is the sender's private round-1 HJKY zero-sharing message for the
	// recipient.
	ZeroR1 *hjky.Round1P2P[G, S]
}

// Validate checks that the private message contains a well-formed HJKY round-1
// payload when the sender is a previous shareholder.
func (m *Round1P2P[G, S]) Validate(p *Participant[G, S], fromID sharing.ID) error {
	if p.isPrevShareholder(fromID) && p.zeroParticipant != nil {
		if m == nil || m.ZeroR1 == nil {
			return ErrValidation.WithMessage("no message")
		}
		if err := m.ZeroR1.Validate(p.zeroParticipant, fromID); err != nil {
			return errs.Wrap(err).WithMessage("invalid message")
		}
	}

	return nil
}

// Round2Broadcast carries the public metadata and verification material that
// previous shareholders publish before next shareholders aggregate fresh
// shares.
type Round2Broadcast[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	// PrevMSP is the MSP underlying the previous sharing that the trusted dealer
	// claims was used for the existing shard.
	PrevMSP *msp.MSP[S]
	// PrevVerificationVector authenticates the sender's existing share under the
	// previous MSP.
	PrevVerificationVector *feldman.VerificationVector[G, S]
	// ZeroVerificationVector authenticates the sender's zero-sharing contribution
	// over the previous-shareholder unanimity access structure.
	ZeroVerificationVector *feldman.VerificationVector[G, S]
	// NextVerificationVectorContribution authenticates the sender's contribution
	// to the aggregated verification vector under the next access structure.
	NextVerificationVectorContribution *feldman.VerificationVector[G, S]
}

// Validate checks that the broadcast contains well-formed metadata and
// verification vectors from a previous shareholder.
func (m *Round2Broadcast[G, S]) Validate(p *Participant[G, S], from sharing.ID) error {
	if !p.isPrevShareholder(from) {
		return nil
	}
	if m == nil || m.PrevMSP == nil || m.PrevVerificationVector == nil || m.ZeroVerificationVector == nil || m.NextVerificationVectorContribution == nil {
		return ErrValidation.WithMessage("no message")
	}
	if !m.PrevVerificationVector.Value().IsColumnVector() || !m.ZeroVerificationVector.Value().IsColumnVector() || !m.NextVerificationVectorContribution.Value().IsColumnVector() {
		return ErrValidation.WithMessage("invalid verification vector")
	}
	if r, _ := m.PrevVerificationVector.Value().Dimensions(); r != int(m.PrevMSP.D()) {
		return ErrValidation.WithMessage("invalid previous verification vector dimensions")
	}
	zero, err := m.ZeroVerificationVector.Value().Get(0, 0)
	if err != nil {
		return ErrValidation.WithMessage("invalid zero verification vector")
	}
	zeroMSP, err := accessstructures.InducedMSP(
		algebra.StructureMustBeAs[algebra.PrimeField[S]](
			algebra.StructureMustBeAs[algebra.PrimeGroup[G, S]](zero.Structure()).ScalarStructure(),
		),
		p.prevUnanimity,
	)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot induce MSP for previous unanimity access structure")
	}
	if r, _ := m.ZeroVerificationVector.Value().Dimensions(); r != int(zeroMSP.D()) {
		return ErrValidation.WithMessage("invalid zero verification vector dimensions")
	}

	basePoint, err := m.NextVerificationVectorContribution.Value().Get(0, 0)
	if err != nil {
		return ErrValidation.WithMessage("invalid next verification vector")
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
	if r, _ := m.NextVerificationVectorContribution.Value().Dimensions(); r != int(nextMSP.D()) {
		return ErrValidation.WithMessage("invalid next verification vector dimensions")
	}

	return nil
}

// Round2P2P carries one previous shareholder's private contribution to a next
// shareholder's redistributed share.
type Round2P2P[G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]] struct {
	// NextShareContribution is the sender's private contribution to the
	// recipient's fresh share under the next access structure.
	NextShareContribution *feldman.Share[S]
}

// Validate checks that the private message contains a well-formed share
// contribution for the recipient.
func (m *Round2P2P[G, S]) Validate(p *Participant[G, S], from sharing.ID) error {
	if !p.isPrevShareholder(from) {
		return nil
	}
	if m == nil || m.NextShareContribution == nil {
		return ErrValidation.WithMessage("no message")
	}
	if p.ctx.HolderID() != m.NextShareContribution.ID() {
		return ErrValidation.WithMessage("invalid next share contribution ID")
	}
	if len(m.NextShareContribution.Value()) == 0 {
		return ErrValidation.WithMessage("empty next share contribution")
	}

	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](m.NextShareContribution.Value()[0].Structure())
	nextMSP, err := accessstructures.InducedMSP(field, p.nextAccessStructures)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot induce MSP for next access structure")
	}
	rows, ok := nextMSP.HoldersToRows().Get(p.ctx.HolderID())
	if !ok {
		return ErrValidation.WithMessage("recipient is not in the next access structure")
	}
	if len(m.NextShareContribution.Value()) != rows.Size() {
		return ErrValidation.WithMessage("invalid next share contribution dimensions")
	}

	return nil
}
