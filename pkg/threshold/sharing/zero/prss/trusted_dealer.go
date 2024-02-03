package prss

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
)

func Deal(config *integration.CohortConfig, prng io.Reader) (map[types.IdentityHash]*Seed, error) {
	n := config.Protocol.TotalParties
	t := config.Protocol.Threshold - 1

	shares := make(map[int]curves.Scalar)
	subSets := NewSubSets(config.Participants, n-t)
	for _, subSet := range subSets {
		var err error
		shares[subSet.Label()], err = config.CipherSuite.Curve.ScalarField().Random(prng)
		if err != nil {
			return nil, errs.WrapRandomSampleFailed(err, "cannot sample random")
		}
	}

	seeds := make(map[types.IdentityHash]*Seed)
	for partyHash, party := range config.Participants.Iter() {
		seeds[partyHash] = &Seed{
			Ra: make(map[int]curves.Scalar),
		}
		for _, subSet := range subSets {
			if subSet.Contains(party) {
				seeds[partyHash].Ra[subSet.Label()] = shares[subSet.Label()]
			}
		}
	}

	return seeds, nil
}
