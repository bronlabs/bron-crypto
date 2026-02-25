package aor

import hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"

// Round1Broadcast carries the commitment to a participant's random seed.
type Round1Broadcast struct {
	Commitment hash_comm.Commitment `cbor:"commitment"`
}

// Round2Broadcast carries the opening (message, witness) for the seed commitment.
type Round2Broadcast struct {
	Message hash_comm.Message `cbor:"message"`
	Witness hash_comm.Witness `cbor:"witness"`
}
