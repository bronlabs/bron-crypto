package przssetup

import (
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/przs"
)

// Round1Broadcast contains round-1 public commitments sent by a participant.
type Round1Broadcast struct {
	Commitments map[sharing.ID]hash_comm.Commitment `cbor:"commitments"`
}

func (*Round1Broadcast) Validate(*Participant) error { return nil }

// Round2P2P contains a round-2 private seed contribution and witness.
type Round2P2P struct {
	SeedContribution [przs.SeedLength]byte `cbor:"seedContribution"`
	Witness          hash_comm.Witness     `cbor:"witness"`
}

func (*Round2P2P) Validate(*Participant) error { return nil }
