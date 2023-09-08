package testutils

import "github.com/copperexchange/krypton/pkg/threshold/dkg/pedersen/testutils"

var (
	MakeDkgParticipants               = testutils.MakeParticipants
	DoDkgRound1                       = testutils.DoDkgRound1
	MapDkgRound1OutputsToRound2Inputs = testutils.MapDkgRound1OutputsToRound2Inputs
	DoDkgRound2                       = testutils.DoDkgRound2
)
