package session

import (
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
	return nil
}

// Round3P2P carries a contribution and its opening witness.
type Round3P2P struct {
	Contribution        [32]byte
	ContributionWitness hash_comm.Witness
}

func (m *Round3P2P) Validate(*Participant, sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round3P2P message")
	}
	return nil
}
