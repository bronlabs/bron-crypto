package aor

import (
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
)

type Round1Broadcast struct {
	Commitment hash_comm.Commitment `cbor:"commitment"`
}

type Round2Broadcast struct {
	Message hash_comm.Message `cbor:"message"`
	Witness hash_comm.Witness `cbor:"witness"`
}
