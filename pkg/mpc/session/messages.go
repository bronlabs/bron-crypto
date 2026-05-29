package session

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// Round1Broadcast carries the commitment key for the session.
type Round1Broadcast struct {
	CommonCommitment hashcom.Commitment
	Ck               *hashcom.CommitmentKey
}

func (m *Round1Broadcast) Validate(*Participant, sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round1Broadcast message")
	}
	if m.CommonCommitment == (hashcom.Commitment{}) {
		return ErrValidation.WithMessage("missing common commitment in Round1Broadcast message")
	}
	if m.Ck == nil || *m.Ck == (hashcom.CommitmentKey{}) {
		return ErrValidation.WithMessage("missing commitment key in Round1Broadcast message")
	}
	return nil
}

type Round2Broadcast struct {
	CommonContribution        [base.CollisionResistanceBytesCeil]byte
	CommonContributionWitness hashcom.Witness
}

func (m *Round2Broadcast) Validate(*Participant, sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round2Broadcast message")
	}
	if m.CommonContribution == ([base.CollisionResistanceBytesCeil]byte{}) {
		return ErrValidation.WithMessage("missing common contribution in Round2Broadcast message")
	}
	if m.CommonContributionWitness == (hashcom.Witness{}) {
		return ErrValidation.WithMessage("missing common contribution witness in Round2Broadcast message")
	}

	return nil
}

// Round2P2P carries a commitment to a per-peer contribution.
type Round2P2P struct {
	PairwiseContributionCommitment hashcom.Commitment
}

func (m *Round2P2P) Validate(*Participant, sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round2P2P message")
	}
	if m.PairwiseContributionCommitment == (hashcom.Commitment{}) {
		return ErrValidation.WithMessage("missing commitment in Round2P2P message")
	}
	return nil
}

// Round3P2P carries a contribution and its opening witness.
type Round3P2P struct {
	PairwiseContribution        [base.CollisionResistanceBytesCeil]byte
	PairwiseContributionWitness hashcom.Witness
}

func (m *Round3P2P) Validate(*Participant, sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round3P2P message")
	}
	if m.PairwiseContribution == ([base.CollisionResistanceBytesCeil]byte{}) {
		return ErrValidation.WithMessage("missing contribution in Round3P2P message")
	}
	if m.PairwiseContributionWitness == (hashcom.Witness{}) {
		return ErrValidation.WithMessage("missing contribution witness in Round3P2P message")
	}
	return nil
}
