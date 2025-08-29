package przsSetup

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
)

type Round1Broadcast struct {
	commitments ds.Map[sharing.ID, hash_comm.Commitment]
}

func (m *Round1Broadcast) Bytes() []byte {
	panic("not used")
}

type Round2P2P struct {
	seedContribution [przs.SeedLength]byte
	witness          hash_comm.Witness
}

func (m *Round2P2P) Bytes() []byte {
	panic("not used")
}
