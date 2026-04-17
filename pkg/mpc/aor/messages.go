package aor

import (
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
)

// Round1Broadcast carries the commitment to a participant's random seed.
type Round1Broadcast struct {
	Commitment hash_comm.Commitment `cbor:"commitment"`
}

func (m *Round1Broadcast) Validate(*Participant, sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round1Broadcast message")
	}
	if m.Commitment == [hash_comm.DigestSize]byte{} {
		return ErrValidation.WithMessage("missing commitment in Round1Broadcast message")
	}
	return nil
}

// Round2Broadcast carries the opening (message, witness) for the seed commitment.
type Round2Broadcast struct {
	Message hash_comm.Message `cbor:"message"`
	Witness hash_comm.Witness `cbor:"witness"`
}

func (m *Round2Broadcast) Validate(p *Participant, _ sharing.ID) error {
	if m == nil {
		return ErrValidation.WithMessage("missing fields in Round2Broadcast message")
	}
	if len(m.Message) != p.size {
		return ErrValidation.WithMessage("invalid message length in Round2Broadcast message. got :%d, need :%d", len(m.Message), p.size)
	}
	if ct.SliceIsZero(m.Message) == ct.True {
		return ErrValidation.WithMessage("missing message in Round2Broadcast message")
	}
	if m.Witness == [hash_comm.DigestSize]byte{} {
		return ErrValidation.WithMessage("missing witness in Round2Broadcast message")
	}
	return nil
}
