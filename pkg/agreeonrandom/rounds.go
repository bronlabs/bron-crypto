package agreeonrandom

import (
	"fmt"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero"
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

func (p *Participant) Round2(round1output map[integration.IdentityKey]*Round1Broadcast) ([]byte, error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	round1output[p.MyIdentityKey] = &Round1Broadcast{
		Ri: p.state.r_i,
	}
	sortRandomnessContributions, err := sortRandomnessContributions(round1output)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't derive r vector")
	}
	for i, sidFromI := range sortRandomnessContributions {
		p.state.transcript.AppendMessage([]byte(fmt.Sprintf("sid contribution from %d", i)), sidFromI)
	}
	randomValue := p.state.transcript.ExtractBytes([]byte("session id"), zero.LambdaBytes)
	p.round++
	return randomValue, nil
}

func hasDuplicate(list []integration.IdentityKey) bool {
	seen := make(map[integration.IdentityKey]bool)
	for _, item := range list {
		if seen[item] {
			return true
		}
		seen[item] = true
	}
	return false
}

func sortRandomnessContributions(allIdentityKeysToRi map[integration.IdentityKey]*Round1Broadcast) ([][]byte, error) {
	identityKeys := make([]integration.IdentityKey, len(allIdentityKeysToRi))
	i := 0
	for identityKey := range allIdentityKeysToRi {
		identityKeys[i] = identityKey
		i++
	}
	if doesHaveDuplicate := hasDuplicate(identityKeys); doesHaveDuplicate {
		return nil, errs.NewDuplicate("duplicate identity keys")
	}
	identityKeys = integration.SortIdentityKeys(identityKeys)
	sortedRVector := make([][]byte, len(allIdentityKeysToRi))
	for i, identityKey := range identityKeys {
		message, exists := allIdentityKeysToRi[identityKey]
		if !exists {
			return nil, errs.NewMissing("message couldn't be found")
		}
		sortedRVector[i] = message.Ri.Bytes()
	}

	return sortedRVector, nil
}
