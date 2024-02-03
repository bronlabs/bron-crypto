package prss

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type Round1P2P struct {
	Ra map[int]curves.Scalar
}

func (p *SetupParticipant) Round1() (map[types.IdentityHash]*Round1P2P, error) {
	dealt, err := Deal(p.cohortConfig, p.prng)
	if err != nil {
		return nil, err
	}

	output := make(map[types.IdentityHash]*Round1P2P)
	for idHash := range p.cohortConfig.Participants.Iter() {
		if idHash == p.myIdentity.Hash() {
			p.state.ra = dealt[idHash].Ra
		} else {
			output[idHash] = &Round1P2P{
				Ra: dealt[idHash].Ra,
			}
		}
	}

	return output, nil
}

func (p *SetupParticipant) Round2(input map[types.IdentityHash]*Round1P2P) *Seed {
	result := make(map[int]curves.Scalar)
	for k, r := range p.state.ra {
		result[k] = r
	}
	for _, r2Input := range input {
		for k, v := range r2Input.Ra {
			result[k] = result[k].Add(v)
		}
	}

	return &Seed{Ra: result}
}
