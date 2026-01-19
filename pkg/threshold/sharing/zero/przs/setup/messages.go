package przsSetup

import (
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs"
)

type Round1Broadcast struct {
	Commitments map[sharing.ID]hash_comm.Commitment `cbor:"commitments"`
}

func (*Round1Broadcast) Bytes() []byte {
	panic("not used")
}

type Round2P2P struct {
	SeedContribution [przs.SeedLength]byte `cbor:"seedContribution"`
	Witness          hash_comm.Witness     `cbor:"witness"`
}

func (*Round2P2P) Bytes() []byte {
	panic("not used")
}
