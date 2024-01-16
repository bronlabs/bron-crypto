package dkg

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tbls/boldyreva02/keygen/dkg"
)

type Participant = dkg.Participant[bls12381.G1]

var NewParticipant = dkg.NewParticipant[bls12381.G1]
