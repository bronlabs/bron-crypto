package przssetup

import (
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/przs"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

// Round1Broadcast contains round-1 public commitments sent by a participant.
type Round1Broadcast struct {
	Commitments map[sharing.ID]hash_comm.Commitment `cbor:"commitments"`
}

func (m *Round1Broadcast) Validate(p *Participant, _ sharing.ID) error {
	for sharingID := range p.quorum.Iter() {
		if sharingID == p.mySharingID {
			continue
		}
		com, ok := m.Commitments[sharingID]
		if !ok {
			return network.ErrInvalidMessage.WithMessage("missing commitment for sharing ID %d", sharingID)
		}
		if com == [hash_comm.DigestSize]byte{} {
			return network.ErrInvalidMessage.WithMessage("empty commitment for sharing ID %d", sharingID)
		}
	}
	return nil
}

// Round2P2P contains a round-2 private seed contribution and witness.
type Round2P2P struct {
	SeedContribution [przs.SeedLength]byte `cbor:"seedContribution"`
	Witness          hash_comm.Witness     `cbor:"witness"`
}

func (m *Round2P2P) Validate(p *Participant, _ sharing.ID) error {
	if ct.SliceIsZero(m.SeedContribution[:]) == ct.True {
		return network.ErrInvalidMessage.WithMessage("seed contribution cannot be all zero")
	}
	if len(m.Witness) == 0 {
		return network.ErrInvalidMessage.WithMessage("missing witness")
	}
	return nil
}
