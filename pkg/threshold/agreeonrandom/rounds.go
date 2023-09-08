package agreeonrandom

import (
	"sort"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/commitments"
	"github.com/copperexchange/knox-primitives/pkg/threshold/sharing/zero/przs"
)

var h = sha3.New256

type Round1Broadcast struct {
	Commitment commitments.Commitment

	_ helper_types.Incomparable
}
type Round2Broadcast struct {
	Ri      curves.Scalar
	Witness commitments.Witness

	_ helper_types.Incomparable
}

func (p *Participant) Round1() (*Round1Broadcast, error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}

	r_i := p.Curve.Scalar().Random(p.prng)
	commitment, witness, err := commitments.Commit(h, r_i.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not commit to the seed for participant %x", p.MyIdentityKey.Hash())
	}
	p.round++
	p.state.r_i = r_i
	p.state.witness = witness
	return &Round1Broadcast{
		Commitment: commitment,
	}, nil
}

func (p *Participant) Round2(round1output map[helper_types.IdentityHash]*Round1Broadcast) (*Round2Broadcast, error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	for key, round1Msg := range round1output {
		if len(round1Msg.Commitment) == 0 {
			return nil, errs.NewInvalidArgument("commitment is empty")
		}
		p.state.receivedCommitments[key] = round1Msg.Commitment
	}
	p.round++
	return &Round2Broadcast{
		Witness: p.state.witness,
		Ri:      p.state.r_i,
	}, nil
}

func (p *Participant) Round3(round2output map[helper_types.IdentityHash]*Round2Broadcast) ([]byte, error) {
	if p.round != 3 {
		return nil, errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}
	for key, message := range round2output {
		if p.state.receivedCommitments[key] == nil {
			return nil, errs.NewIdentifiableAbort(key, "could not find commitment for participant %x", key)
		}
		if err := commitments.Open(h, message.Ri.Bytes(), p.state.receivedCommitments[key], message.Witness); err != nil {
			return nil, errs.WrapIdentifiableAbort(err, key, "commitment from participant with sharing id can't be opened")
		}
	}
	round2output[p.MyIdentityKey.Hash()] = &Round2Broadcast{
		Ri: p.state.r_i,
	}
	sortRandomnessContributions, err := p.sortRandomnessContributions(round2output)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't derive r vector")
	}
	p.state.transcript.AppendMessages("sid contribution", sortRandomnessContributions...)
	randomValue, err := p.state.transcript.ExtractBytes("session id", przs.LambdaBytes)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't derive random value")
	}
	p.round++
	return randomValue, nil
}

func (p *Participant) sortRandomnessContributions(allIdentityKeysToRi map[helper_types.IdentityHash]*Round2Broadcast) ([][]byte, error) {
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
