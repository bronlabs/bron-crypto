package dkg

import (
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/keygen/dkg"
)

type Participant = dkg.Participant[bls.G1]

var NewParticipant = dkg.NewParticipant[bls.G1]
