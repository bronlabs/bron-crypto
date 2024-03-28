package agreeonrandom

import (
	"sort"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

func (p *Participant) sortRandomnessContributions(allIdentityKeysToRi network.RoundMessages[*Round2Broadcast]) ([][]byte, error) {
	sortedIdentityIndices := p.IdentitySpace.Keys()
	sort.Slice(sortedIdentityIndices, func(i, j int) bool { return sortedIdentityIndices[i] < sortedIdentityIndices[j] })
	sortedRVector := make([][]byte, allIdentityKeysToRi.Size())
	for i, identityIndex := range sortedIdentityIndices {
		identityKey, exists := p.IdentitySpace.Get(identityIndex)
		if !exists {
			return nil, errs.NewMissing("couldn't find identity key %d", identityIndex)
		}
		message, exists := allIdentityKeysToRi.Get(identityKey)
		if !exists {
			return nil, errs.NewMissing("message couldn't be found")
		}
		sortedRVector[i] = message.Ri.Bytes()
	}

	return sortedRVector, nil
}
