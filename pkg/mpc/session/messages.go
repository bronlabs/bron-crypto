package session

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// Round1Broadcast carries the commitment key for the session.
type Round1Broadcast struct {
	Ck hash_comm.Key
}

func (m *Round1Broadcast) Validate(*Participant, sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round1Broadcast message")
	}
	if ct.SliceIsZero(m.Ck[:]) == ct.True {
		return ErrValidation.WithMessage("missing commitment key in Round1Broadcast message")
	}
	return nil
}

// Round2P2P carries a commitment to a per-peer contribution.
type Round2P2P struct {
	Commitment hash_comm.Commitment
}

func (m *Round2P2P) Validate(*Participant, sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round2P2P message")
	}
	if ct.SliceIsZero(m.Commitment[:]) == ct.True {
		return ErrValidation.WithMessage("missing commitment in Round2P2P message")
	}
	return nil
}

// Round3P2P carries a contribution and its opening witness.
type Round3P2P struct {
	Contribution        [base.CollisionResistanceBytesCeil]byte
	ContributionWitness hash_comm.Witness
}

func (m *Round3P2P) Validate(*Participant, sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round3P2P message")
	}
	if ct.SliceIsZero(m.Contribution[:]) == ct.True {
		return ErrValidation.WithMessage("missing contribution in Round3P2P message")
	}
	if ct.SliceIsZero(m.ContributionWitness[:]) == ct.True {
		return ErrValidation.WithMessage("missing contribution witness in Round3P2P message")
	}
	return nil
}
