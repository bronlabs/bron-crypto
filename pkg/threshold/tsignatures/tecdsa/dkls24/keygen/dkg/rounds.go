package dkg

import (
	"encoding/hex"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro"
	zeroSetup "github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/setup"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
)

type Round1Broadcast = gennaro.Round1Broadcast
type Round1P2P struct {
	Gennaro      *gennaro.Round1P2P
	ZeroSampling *zeroSetup.Round1P2P
	BaseOTSender bbot.Round1P2P

	_ types.Incomparable
}

type Round2Broadcast = gennaro.Round2Broadcast
type Round2P2P struct {
	ZeroSampling   *zeroSetup.Round2P2P
	BaseOTReceiver bbot.Round2P2P

	_ types.Incomparable
}

func (p *Participant) Round1() (*Round1Broadcast, map[types.IdentityHash]*Round1P2P, error) {
	gennaroBroadcast, gennaroP2P, err := p.GennaroParty.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "gennaro round 1 failed")
	}
	zeroSamplingP2P, err := p.ZeroSamplingParty.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "zero sampling round 1 failed")
	}
	baseOtP2P := map[types.IdentityHash]bbot.Round1P2P{}
	for identity, party := range p.BaseOTSenderParties {
		r1out, err := party.Round1()
		baseOtP2P[identity] = r1out
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "BaseOT as sender for identity %x", hex.EncodeToString(identity[:]))
		}
	}

	p2pOutput := make(map[types.IdentityHash]*Round1P2P, len(gennaroP2P))

	for identity, message := range gennaroP2P {
		p2pOutput[identity] = &Round1P2P{
			Gennaro:      message,
			ZeroSampling: zeroSamplingP2P[identity],
			BaseOTSender: baseOtP2P[identity],
		}
	}
	return gennaroBroadcast, p2pOutput, nil
}

func (p *Participant) Round2(round1outputBroadcast map[types.IdentityHash]*Round1Broadcast, round1outputP2P map[types.IdentityHash]*Round1P2P) (*Round2Broadcast, map[types.IdentityHash]*Round2P2P, error) {
	gennaroRound1outputP2P := map[types.IdentityHash]*gennaro.Round1P2P{}
	zeroSamplingRound1Output := map[types.IdentityHash]*zeroSetup.Round1P2P{}
	baseOtRound1Output := map[types.IdentityHash]bbot.Round1P2P{}
	for identity, message := range round1outputP2P {
		gennaroRound1outputP2P[identity] = message.Gennaro
		zeroSamplingRound1Output[identity] = message.ZeroSampling
		baseOtRound1Output[identity] = message.BaseOTSender
	}
	gennaroBroadcast, err := p.GennaroParty.Round2(round1outputBroadcast, gennaroRound1outputP2P)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "gennaro round 2 failed")
	}
	zeroSamplingP2P, err := p.ZeroSamplingParty.Round2(zeroSamplingRound1Output)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "zero sampling round 2 failed")
	}
	baseOTP2P := map[types.IdentityHash]bbot.Round2P2P{}
	for identity, receiver := range p.BaseOTReceiverParties {
		baseOTP2P[identity], err = receiver.Round2(baseOtRound1Output[identity])
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "base OT as receiver for identity %x", hex.EncodeToString(identity[:]))
		}
	}
	p2pOutput := make(map[types.IdentityHash]*Round2P2P, len(zeroSamplingP2P))
	for identity, message := range zeroSamplingP2P {
		p2pOutput[identity] = &Round2P2P{
			ZeroSampling:   message,
			BaseOTReceiver: baseOTP2P[identity],
		}
	}

	return gennaroBroadcast, p2pOutput, nil
}

func (p *Participant) Round3(round2outputBroadcast map[types.IdentityHash]*Round2Broadcast, round2outputP2P map[types.IdentityHash]*Round2P2P) (s *dkls24.Shard, err error) {
	zeroSamplingRound2Output := map[types.IdentityHash]*zeroSetup.Round2P2P{}
	baseOtRound2Output := map[types.IdentityHash]bbot.Round2P2P{}
	for identity, message := range round2outputP2P {
		zeroSamplingRound2Output[identity] = message.ZeroSampling
		baseOtRound2Output[identity] = message.BaseOTReceiver
	}
	p.Shard.SigningKeyShare, p.Shard.PublicKeyShares, err = p.GennaroParty.Round3(round2outputBroadcast)
	if err != nil {
		return nil, errs.WrapFailed(err, "gennaro round 3 failed")
	}
	p.Shard.PairwiseSeeds, err = p.ZeroSamplingParty.Round3(zeroSamplingRound2Output)
	if err != nil {
		return nil, errs.WrapFailed(err, "zero sampling round 3 failed")
	}
	for identity, sender := range p.BaseOTSenderParties {
		err = sender.Round3(baseOtRound2Output[identity])
		if err != nil {
			return nil, errs.WrapFailed(err, "base OT as sender for identity %x", hex.EncodeToString(identity[:]))
		}
	}
	p.Shard.PairwiseBaseOTs = map[types.IdentityHash]*dkls24.BaseOTConfig{}
	for _, identity := range p.GetCohortConfig().Participants.Iter() {
		if identity.PublicKey().Equal(p.MyAuthKey.PublicKey()) {
			continue
		}
		p.Shard.PairwiseBaseOTs[identity.Hash()] = &dkls24.BaseOTConfig{
			AsSender:   p.BaseOTSenderParties[identity.Hash()].Output,
			AsReceiver: p.BaseOTReceiverParties[identity.Hash()].Output,
		}
	}
	// by now, it's fully computed
	return p.Shard, nil
}
