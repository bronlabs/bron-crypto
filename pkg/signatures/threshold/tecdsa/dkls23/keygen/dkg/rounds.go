package dkg

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/dkg/gennaro"
	"github.com/copperexchange/crypto-primitives-go/pkg/ot/base/vsot"
	zeroSetup "github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero/setup"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/dkls23"
)

type Round1Broadcast = gennaro.Round1Broadcast
type Round1P2P struct {
	Gennaro      *gennaro.Round1P2P
	ZeroSampling *zeroSetup.Round1P2P
	VSOTSender   *vsot.Round1P2P
}

type Round2Broadcast = gennaro.Round2Broadcast
type Round2P2P struct {
	ZeroSampling *zeroSetup.Round2P2P
	VSOTReceiver vsot.Round2P2P
}

// Acting as sender
type Round3P2P = vsot.Round3P2P

// Acting as receiver
type Round4P2P = vsot.Round4P2P

// Acting as sender
type Round5P2P = vsot.Round5P2P

func (p *Participant) Round1() (*Round1Broadcast, map[integration.IdentityKey]*Round1P2P, error) {
	gennaroBroadcast, gennaroP2P, err := p.GennaroParty.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "gennaro round 1 failed")
	}
	zeroSamplingP2P, err := p.ZeroSamplingParty.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "zero sampling round 1 failed")
	}
	baseOTP2P := map[integration.IdentityKey]*vsot.Round1P2P{}
	for identity, party := range p.BaseOTSenderParties {
		proof, publicKey, err := party.Round1ComputeAndZkpToPublicKey()
		baseOTP2P[identity] = &vsot.Round1P2P{
			Proof:     proof,
			PublicKey: publicKey,
		}
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "vsot as sender for identity %x", identity.PublicKey().ToAffineCompressed())
		}
	}

	p2pOutput := make(map[integration.IdentityKey]*Round1P2P, len(gennaroP2P))

	for identity, message := range gennaroP2P {
		p2pOutput[identity] = &Round1P2P{
			Gennaro:      message,
			ZeroSampling: zeroSamplingP2P[identity],
			VSOTSender:   baseOTP2P[identity],
		}
	}
	return gennaroBroadcast, p2pOutput, nil
}

func (p *Participant) Round2(round1outputBroadcast map[integration.IdentityKey]*Round1Broadcast, round1outputP2P map[integration.IdentityKey]*Round1P2P) (*Round2Broadcast, map[integration.IdentityKey]*Round2P2P, error) {
	gennaroRound1outputP2P := map[integration.IdentityKey]*gennaro.Round1P2P{}
	zeroSamplingRound1Output := map[integration.IdentityKey]*zeroSetup.Round1P2P{}
	vsotRound1Output := map[integration.IdentityKey]*vsot.Round1P2P{}
	for identity, message := range round1outputP2P {
		gennaroRound1outputP2P[identity] = message.Gennaro
		zeroSamplingRound1Output[identity] = message.ZeroSampling
		vsotRound1Output[identity] = message.VSOTSender
	}
	gennaroBroadcast, err := p.GennaroParty.Round2(round1outputBroadcast, gennaroRound1outputP2P)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "gennaro round 2 failed")
	}
	zeroSamplingP2P, err := p.ZeroSamplingParty.Round2(zeroSamplingRound1Output)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "zero sampling round 2 failed")
	}
	baseOTP2P := map[integration.IdentityKey]vsot.Round2P2P{}
	for identity, receiver := range p.BaseOTReceiverParties {
		baseOTP2P[identity], err = receiver.Round2VerifySchnorrAndPadTransfer(vsotRound1Output[identity].PublicKey, vsotRound1Output[identity].Proof)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "vsot as receiver for identity %x", identity.PublicKey().ToAffineCompressed())
		}
	}
	p2pOutput := make(map[integration.IdentityKey]*Round2P2P, len(zeroSamplingP2P))
	for identity, message := range zeroSamplingP2P {
		p2pOutput[identity] = &Round2P2P{
			ZeroSampling: message,
			VSOTReceiver: baseOTP2P[identity],
		}
	}

	return gennaroBroadcast, p2pOutput, nil
}

func (p *Participant) Round3(round2outputBroadcast map[integration.IdentityKey]*Round2Broadcast, round2outputP2P map[integration.IdentityKey]*Round2P2P) (map[integration.IdentityKey]Round3P2P, error) {
	zeroSamplingRound2Output := map[integration.IdentityKey]*zeroSetup.Round2P2P{}
	vsotRound2Output := map[integration.IdentityKey]vsot.Round2P2P{}
	for identity, message := range round2outputP2P {
		zeroSamplingRound2Output[identity] = message.ZeroSampling
		vsotRound2Output[identity] = message.VSOTReceiver
	}
	var err error
	p.Shard.SigningKeyShare, p.Shard.PublicKeyShares, err = p.GennaroParty.Round3(round2outputBroadcast)
	if err != nil {
		return nil, errs.WrapFailed(err, "gennaro round 3 failed")
	}
	p.Shard.PairwiseSeeds, err = p.ZeroSamplingParty.Round3(zeroSamplingRound2Output)
	if err != nil {
		return nil, errs.WrapFailed(err, "zero sampling round 3 failed")
	}
	baseOTP2P := map[integration.IdentityKey]vsot.Round3P2P{}
	for identity, sender := range p.BaseOTSenderParties {
		baseOTP2P[identity], err = sender.Round3PadTransfer(vsotRound2Output[identity])
		if err != nil {
			return nil, errs.WrapFailed(err, "vsot as sender for identity %x", identity.PublicKey().ToAffineCompressed())
		}
	}
	return baseOTP2P, nil
}

func (p *Participant) Round4(round3output map[integration.IdentityKey]Round3P2P) (map[integration.IdentityKey]Round4P2P, error) {
	baseOTP2P := map[integration.IdentityKey]vsot.Round4P2P{}
	for identity, receiver := range p.BaseOTReceiverParties {
		baseOTP2P[identity] = receiver.Round4RespondToChallenge(round3output[identity])
	}
	return baseOTP2P, nil
}

func (p *Participant) Round5(round4output map[integration.IdentityKey]Round4P2P) (map[integration.IdentityKey]Round5P2P, error) {
	var err error
	baseOTP2P := map[integration.IdentityKey]vsot.Round5P2P{}
	for identity, sender := range p.BaseOTSenderParties {
		baseOTP2P[identity], err = sender.Round5Verify(round4output[identity])
		if err != nil {
			return nil, errs.WrapFailed(err, "vsot as sender for identity %x", identity.PublicKey().ToAffineCompressed())
		}
	}
	return baseOTP2P, nil
}

func (p *Participant) Round6(round5output map[integration.IdentityKey]Round5P2P) (*dkls23.Shard, error) {
	for identity, receiver := range p.BaseOTReceiverParties {
		if err := receiver.Round6Verify(round5output[identity]); err != nil {
			return nil, errs.WrapFailed(err, "vsot as receiver for indentity %x", identity.PublicKey().ToAffineCompressed())
		}
	}
	p.Shard.PairwiseBaseOTs = map[integration.IdentityKey]*dkls23.BaseOTConfig{}
	for _, identity := range p.GetCohortConfig().Participants {
		if identity.PublicKey().Equal(p.MyIdentityKey.PublicKey()) {
			continue
		}
		p.Shard.PairwiseBaseOTs[identity] = &dkls23.BaseOTConfig{
			AsSender:   p.BaseOTSenderParties[identity].Output,
			AsReceiver: p.BaseOTReceiverParties[identity].Output,
		}
	}
	// by now, it's fully computed
	return p.Shard, nil
}
