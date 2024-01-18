package cogen

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
)

type Round1OutbandBroadcast struct {
	PublicKey curves.Point
}

type Round2Broadcast struct {
	Certificate []byte
}

func (p *Participant) Round1() (*Round1OutbandBroadcast, error) {
	if p.round != 1 {
		return nil, errs.NewInvalidRound("round mismatch %d != 1", p.round)
	}
	outputBroadcast := &Round1OutbandBroadcast{
		PublicKey: p.myAuthKey.PublicKey(),
	}
	p.round++
	return outputBroadcast, nil
}

func (p *Participant) Round2(round2Input map[types.IdentityHash]*Round1OutbandBroadcast) (*Round2Broadcast, error) {
	if p.round != 2 {
		return nil, errs.NewInvalidRound("round mismatch %d != 2", p.round)
	}
	p.otherGroups = make(map[types.IdentityHash]integration.IdentityKey)
	cohortCertificateMessage := &CohortCertificateMessage{
		Groups: make([]curves.Point, len(round2Input)+1),
	}
	cohortCertificateMessage.Groups[0] = p.myAuthKey.PublicKey()
	i := 1
	for _, round1OutbandBroadcast := range round2Input {
		cohortCertificateMessage.Groups[i] = round1OutbandBroadcast.PublicKey
		identityKey, err := p.newCogenIdentityKey(round1OutbandBroadcast.PublicKey)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not create identity key")
		}
		p.otherGroups[identityKey.Hash()] = identityKey
		i++
	}
	p.signingMessage = cohortCertificateMessage.Encode()
	certificate := p.myAuthKey.Sign(p.signingMessage)
	p.round++
	return &Round2Broadcast{
		Certificate: certificate,
	}, nil
}

func (p *Participant) Round3(round3Input map[types.IdentityHash]*Round2Broadcast) error {
	if p.round != 3 {
		return errs.NewInvalidRound("round mismatch %d != 3", p.round)
	}
	for id, round2OutbandBroadcast := range round3Input {
		err := p.otherGroups[id].Verify(round2OutbandBroadcast.Certificate, p.signingMessage)
		if err != nil {
			return errs.WrapIdentifiableAbort(err, id, "could not verify cohort certificate")
		}
	}
	return nil
}
