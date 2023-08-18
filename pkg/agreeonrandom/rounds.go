package agreeonrandom

import (
	"sort"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero"
)

type Round1Broadcast struct {
	Ri curves.Scalar

	_ helper_types.Incomparable
}

func (p *Participant) Round1() (*Round1Broadcast, error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}
	p.state.r_i = p.Curve.Scalar().Random(p.prng)
	p.round++
	return &Round1Broadcast{
		Ri: p.state.r_i,
	}, nil
}

func (p *Participant) Round2(round1output map[helper_types.IdentityHash]*Round1Broadcast) ([]byte, error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	round1output[p.MyIdentityKey.Hash()] = &Round1Broadcast{
		Ri: p.state.r_i,
	}
	sortRandomnessContributions, err := p.sortRandomnessContributions(round1output)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't derive r vector")
	}
	p.state.transcript.AppendMessages("sid contribution", sortRandomnessContributions...)
	randomValue := p.state.transcript.ExtractBytes("session id", zero.LambdaBytes)
	p.round++
	return randomValue, nil
}

func (p *Participant) sortRandomnessContributions(allIdentityKeysToRi map[helper_types.IdentityHash]*Round1Broadcast) ([][]byte, error) {
	sortedSharingIds := make([]int, len(allIdentityKeysToRi))
	i := 0
	for sharingId := range p.SharingIdToIdentity {
		sortedSharingIds[i] = sharingId
		i++
	}

	sort.Ints(sortedSharingIds)
	sortedRVector := make([][]byte, len(allIdentityKeysToRi))
	for i, sharingId := range sortedSharingIds {
		identityKey := p.SharingIdToIdentity[sharingId]
		message, exists := allIdentityKeysToRi[identityKey.Hash()]
		if !exists {
			return nil, errs.NewMissing("message couldn't be found")
		}
		sortedRVector[i] = message.Ri.Bytes()
	}

	return sortedRVector, nil
}
