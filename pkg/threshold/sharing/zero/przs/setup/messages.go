package przsSetup

import (
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
)

type Round1Broadcast struct {
	Commitments map[sharing.ID]hash_comm.Commitment `cbor:"1"`
}

func (m *Round1Broadcast) Bytes() []byte {
	panic("not used")
}

type Round2P2P struct {
	SeedContribution [przs.SeedLength]byte `cbor:"1"`
	Witness          hash_comm.Witness     `cbor:"2"`
}

func (m *Round2P2P) Bytes() []byte {
	panic("not used")
}
