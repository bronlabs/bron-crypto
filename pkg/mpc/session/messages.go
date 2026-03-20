package session

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// Round1Broadcast carries the commitment key for the session.
type Round1Broadcast struct {
	Ck hash_comm.Key
}

func (*Round1Broadcast) Validate(*Participant, sharing.ID) error { return nil }

// Round2P2P carries a commitment to a per-peer contribution.
type Round2P2P struct {
	Commitment hash_comm.Commitment
}

func (*Round2P2P) Validate(*Participant, sharing.ID) error { return nil }

// Round3P2P carries a contribution and its opening witness.
type Round3P2P struct {
	Contribution        [base.CollisionResistanceBytesCeil]byte
	ContributionWitness hash_comm.Witness
}

func (*Round3P2P) Validate(*Participant, sharing.ID) error { return nil }
