package session

import hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"

// Round1Broadcast carries the commitment key for the session.
type Round1Broadcast struct {
	Ck hash_comm.Key
}

// Round2P2P carries a commitment to a per-peer contribution.
type Round2P2P struct {
	Commitment hash_comm.Commitment
}

// Round3P2P carries a contribution and its opening witness.
type Round3P2P struct {
	Contribution        [32]byte
	ContributionWitness hash_comm.Witness
}
