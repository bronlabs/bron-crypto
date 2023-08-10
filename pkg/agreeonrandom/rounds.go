package agreeonrandom

import (
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashmap"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero"
)

type Round1Broadcast struct {
	Ri curves.Scalar
}

func (p *Participant) Round1() (*Round1Broadcast, error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}
	p.state.r_i = p.Curve.Scalar.Random(p.prng)
	p.round++
	return &Round1Broadcast{
		Ri: p.state.r_i,
	}, nil
}

func (p *Participant) Round2(round1output *hashmap.HashMap[integration.IdentityKey, *Round1Broadcast]) ([]byte, error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	round1output.Put(p.MyIdentityKey, &Round1Broadcast{
		Ri: p.state.r_i,
	})
	sortRandomnessContributions, err := sortRandomnessContributions(round1output)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't derive r vector")
	}
	p.state.transcript.AppendMessages("sid contribution", sortRandomnessContributions...)
	randomValue := p.state.transcript.ExtractBytes("session id", zero.LambdaBytes)
	p.round++
	return randomValue, nil
}

func sortRandomnessContributions(allIdentityKeysToRi *hashmap.HashMap[integration.IdentityKey, *Round1Broadcast]) ([][]byte, error) {
	identityKeys := make([]integration.IdentityKey, allIdentityKeysToRi.Size())
	i := 0
	for _, identityKey := range allIdentityKeysToRi.Keys() {
		identityKeys[i] = identityKey
		i++
	}
	identityKeys = integration.SortIdentityKeys(identityKeys)
	sortedRVector := make([][]byte, allIdentityKeysToRi.Size())
	for i, identityKey := range identityKeys {
		message, exists := allIdentityKeysToRi.Get(identityKey)
		if !exists {
			return nil, errs.NewMissing("message couldn't be found")
		}
		sortedRVector[i] = message.Ri.Bytes()
	}

	return sortedRVector, nil
}
