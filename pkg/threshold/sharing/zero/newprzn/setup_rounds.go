package newprzn

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type Round1P2P struct {
	Ra map[int]curves.Scalar
}

func (p *SetupParticipant) Round1() (map[types.IdentityHash]*Round1P2P, error) {
	shares := make(map[int]curves.Scalar)
	for _, maximalUnqualifiedSet := range p.maximalUnqualifiedSets {
		var err error
		shares[maximalUnqualifiedSet.Label()], err = p.field.Random(p.prng)
		if err != nil {
			return nil, err
		}
	}

	shareVector := make(map[types.IdentityHash]map[int]curves.Scalar)
	for idHash := range p.parties.Iter() {
		shareVector[idHash] = make(map[int]curves.Scalar)
	}

	for _, maximalUnqualifiedSet := range p.maximalUnqualifiedSets {
		for idHash, party := range p.parties.Iter() {
			if maximalUnqualifiedSet.Contains(party) {
				shareVector[idHash][maximalUnqualifiedSet.Label()] = shares[maximalUnqualifiedSet.Label()]
			}
		}
	}

	output := make(map[types.IdentityHash]*Round1P2P)
	for idHash := range p.parties.Iter() {
		if idHash == p.myIdentity.Hash() {
			p.state.ra = shareVector[p.myIdentity.Hash()]
		}
		output[idHash] = &Round1P2P{
			Ra: shareVector[idHash],
		}
	}

	return output, nil
}

func (p *SetupParticipant) Round2(input map[types.IdentityHash]*Round1P2P) map[int]curves.Scalar {
	result := make(map[int]curves.Scalar)
	for k := range p.state.ra {
		result[k] = k256.NewCurve().ScalarField().Zero()
	}
	for _, r2Input := range input {
		for k, v := range r2Input.Ra {
			result[k] = result[k].Add(v)
		}
	}
	for k, v := range p.state.ra {
		result[k] = result[k].Add(v)
	}

	return result
}
