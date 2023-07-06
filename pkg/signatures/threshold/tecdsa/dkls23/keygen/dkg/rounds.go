package dkg

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/dkg/pedersen"
	zeroSetup "github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero/setup"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/dkls23"
)

type Round1Broadcast struct {
	Pedersen     *pedersen.Round1Broadcast
	ZeroSampling *zeroSetup.Round1Broadcast
}

type Round2Broadcast = pedersen.Round2Broadcast

type Round2P2P struct {
	Pedersen     *pedersen.Round2P2P
	ZeroSampling *zeroSetup.Round2P2P
}

type Round3P2P = zeroSetup.Round3P2P

func (p *Participant) Round1() (*Round1Broadcast, error) {
	pedersen, err := p.pedersenParty.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "pedersen round 1 failed")
	}
	zeroSampling, err := p.zeroSamplingParty.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "zero sampling round 1 failed")
	}
	return &Round1Broadcast{
		Pedersen:     pedersen,
		ZeroSampling: zeroSampling,
	}, nil
}

func (p *Participant) Round2(round1output map[integration.IdentityKey]*Round1Broadcast) (*Round2Broadcast, map[integration.IdentityKey]*Round2P2P, error) {
	pedersenRound1output := make(map[integration.IdentityKey]*pedersen.Round1Broadcast, len(round1output))
	zeroSamplingRound1Output := make(map[integration.IdentityKey]*zeroSetup.Round1Broadcast, len(round1output))
	for identity, message := range round1output {
		pedersenRound1output[identity] = message.Pedersen
		zeroSamplingRound1Output[identity] = message.ZeroSampling
	}

	pedersenBroadcast, pedersenP2P, err := p.pedersenParty.Round2(pedersenRound1output)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "pedersen round 2 failed")
	}

	zeroSamplingP2P, err := p.zeroSamplingParty.Round2(zeroSamplingRound1Output)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "zero sampling round 2 failed")
	}
	p2pOutput := make(map[integration.IdentityKey]*Round2P2P, len(pedersenP2P))
	for identity, message := range pedersenP2P {
		p2pOutput[identity] = &Round2P2P{
			Pedersen:     message,
			ZeroSampling: zeroSamplingP2P[identity],
		}
	}
	return pedersenBroadcast, p2pOutput, nil
}

func (p *Participant) Round3(round2outputBroadcast map[integration.IdentityKey]*Round2Broadcast, round2outputP2P map[integration.IdentityKey]*Round2P2P) (map[integration.IdentityKey]*Round3P2P, error) {
	pedersenRound2outputP2P := map[integration.IdentityKey]*pedersen.Round2P2P{}
	zeroSamplingRound2Output := map[integration.IdentityKey]*zeroSetup.Round2P2P{}
	for identity, message := range round2outputP2P {
		pedersenRound2outputP2P[identity] = message.Pedersen
		zeroSamplingRound2Output[identity] = message.ZeroSampling
	}
	signingKeyShare, publicKeyShares, err := p.pedersenParty.Round3(round2outputBroadcast, pedersenRound2outputP2P)
	if err != nil {
		return nil, errs.WrapFailed(err, "pedersen round 3 failed")
	}
	p.state = &state{
		signingKeyShare: signingKeyShare,
		publicKeyShares: publicKeyShares,
	}

	output, err := p.zeroSamplingParty.Round3(zeroSamplingRound2Output)
	if err != nil {
		return nil, errs.WrapFailed(err, "zero sampling round 3 failed")
	}
	return output, nil
}

func (p *Participant) Round4(round3output map[integration.IdentityKey]*Round3P2P) (*dkls23.Shard, error) {
	pairwiseSeeds, err := p.zeroSamplingParty.Round4(round3output)
	if err != nil {
		return nil, errs.WrapFailed(err, "zero sampling round 4 failed")
	}
	if p.state == nil {
		return nil, errs.NewFailed("output of pedersen missing")
	}
	if p.state.signingKeyShare == nil {
		return nil, errs.NewFailed("output of pedersen missing: signing key share")
	}
	if p.state.publicKeyShares == nil {
		return nil, errs.NewFailed("output of pedersen missing: public key shares")
	}
	return &dkls23.Shard{
		SigningKeyShare: p.state.signingKeyShare,
		PublicKeyShares: p.state.publicKeyShares,
		PairwiseSeeds:   pairwiseSeeds,
	}, nil
}
