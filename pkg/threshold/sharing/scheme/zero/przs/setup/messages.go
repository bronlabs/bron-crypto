package przssetup

import (
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/zero/przs"
)

// Round1Broadcast contains round-1 public commitments sent by a participant.
type Round1Broadcast struct {
	Commitments map[sharing.ID]hash_comm.Commitment `cbor:"commitments"`
}

// Bytes implements network.Message.
func (*Round1Broadcast) Bytes() []byte {
	panic("not used")
}

// Round2P2P contains a round-2 private seed contribution and witness.
type Round2P2P struct {
	SeedContribution [przs.SeedLength]byte `cbor:"seedContribution"`
	Witness          hash_comm.Witness     `cbor:"witness"`
}

// Bytes implements network.Message.
func (*Round2P2P) Bytes() []byte {
	panic("not used")
}
