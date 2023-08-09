package dkg

import (
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashmap"
	"github.com/copperexchange/knox-primitives/pkg/dkg/gennaro"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot"
	zeroSetup "github.com/copperexchange/knox-primitives/pkg/sharing/zero/setup"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23"
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

func (p *Participant) Round1() (*Round1Broadcast, *hashmap.HashMap[integration.IdentityKey, *Round1P2P], error) {
	gennaroBroadcast, gennaroP2P, err := p.GennaroParty.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "gennaro round 1 failed")
	}
	zeroSamplingP2P, err := p.ZeroSamplingParty.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "zero sampling round 1 failed")
	}
	baseOTP2P := hashmap.NewHashMap[integration.IdentityKey, *vsot.Round1P2P]()
	for identity, party := range p.BaseOTSenderParties.GetMap() {
		proof, publicKey, err := party.Round1ComputeAndZkpToPublicKey()
		baseOTP2P.Put(identity, &vsot.Round1P2P{
			Proof:     proof,
			PublicKey: publicKey,
		})
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "vsot as sender for identity %x", party.PublicKey.ToAffineCompressed())
		}
	}

	p2pOutput := hashmap.NewHashMap[integration.IdentityKey, *Round1P2P]()
	for identity, message := range gennaroP2P.GetMap() {
		zeroSamplingMsg, found := zeroSamplingP2P.Get(identity)
		if !found {
			return nil, nil, errs.NewFailed("zero sampling p2p output missing")
		}
		baseOTP2PMsg, found := baseOTP2P.Get(identity)
		if !found {
			return nil, nil, errs.NewFailed("base ot p2p output missing")
		}
		p2pOutput.Put(identity, &Round1P2P{
			Gennaro:      message,
			ZeroSampling: zeroSamplingMsg,
			VSOTSender:   baseOTP2PMsg,
		})
	}
	return gennaroBroadcast, p2pOutput, nil
}

func (p *Participant) Round2(round1outputBroadcast *hashmap.HashMap[integration.IdentityKey, *Round1Broadcast], round1outputP2P *hashmap.HashMap[integration.IdentityKey, *Round1P2P]) (*Round2Broadcast, *hashmap.HashMap[integration.IdentityKey, *Round2P2P], error) {
	gennaroRound1outputP2P := hashmap.NewHashMap[integration.IdentityKey, *gennaro.Round1P2P]()
	zeroSamplingRound1Output := hashmap.NewHashMap[integration.IdentityKey, *zeroSetup.Round1P2P]()
	vsotRound1Output := hashmap.NewHashMap[integration.IdentityKey, *vsot.Round1P2P]()
	for identity, message := range round1outputP2P.GetMap() {
		gennaroRound1outputP2P.Put(identity, message.Gennaro)
		zeroSamplingRound1Output.Put(identity, message.ZeroSampling)
		vsotRound1Output.Put(identity, message.VSOTSender)
	}
	gennaroBroadcast, err := p.GennaroParty.Round2(round1outputBroadcast, gennaroRound1outputP2P)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "gennaro round 2 failed")
	}
	zeroSamplingP2P, err := p.ZeroSamplingParty.Round2(zeroSamplingRound1Output)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "zero sampling round 2 failed")
	}
	baseOTP2P := hashmap.NewHashMap[integration.IdentityKey, vsot.Round2P2P]()
	for _, identity := range p.BaseOTReceiverParties.Keys() {
		receiver, found := p.BaseOTReceiverParties.Get(identity)
		if !found {
			return nil, nil, errs.NewFailed("base ot receiver party missing")
		}
		output, found := vsotRound1Output.Get(identity)
		if !found {
			return nil, nil, errs.NewFailed("vsot round output missing")
		}
		baseOTP2PMsg, err := receiver.Round2VerifySchnorrAndPadTransfer(output.PublicKey, output.Proof)
		baseOTP2P.Put(identity, baseOTP2PMsg)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "vsot as receiver for identity %x", identity.PublicKey().ToAffineCompressed())
		}
	}
	p2pOutput := hashmap.NewHashMap[integration.IdentityKey, *Round2P2P]()
	for identity, message := range zeroSamplingP2P.GetMap() {
		baseOTP2PMsg, found := baseOTP2P.Get(identity)
		if !found {
			return nil, nil, errs.NewFailed("base ot p2p output missing")
		}
		p2pOutput.Put(identity, &Round2P2P{
			ZeroSampling: message,
			VSOTReceiver: baseOTP2PMsg,
		})
	}

	return gennaroBroadcast, p2pOutput, nil
}

func (p *Participant) Round3(round2outputBroadcast *hashmap.HashMap[integration.IdentityKey, *Round2Broadcast], round2outputP2P *hashmap.HashMap[integration.IdentityKey, *Round2P2P]) (*hashmap.HashMap[integration.IdentityKey, Round3P2P], error) {
	zeroSamplingRound2Output := hashmap.NewHashMap[integration.IdentityKey, *zeroSetup.Round2P2P]()
	vsotRound2Output := hashmap.NewHashMap[integration.IdentityKey, vsot.Round2P2P]()
	for identity, message := range round2outputP2P.GetMap() {
		zeroSamplingRound2Output.Put(identity, message.ZeroSampling)
		vsotRound2Output.Put(identity, message.VSOTReceiver)
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
	baseOTP2P := hashmap.NewHashMap[integration.IdentityKey, vsot.Round3P2P]()
	for _, identity := range p.BaseOTSenderParties.Keys() {
		sender, found := p.BaseOTSenderParties.Get(identity)
		if !found {
			return nil, errs.NewFailed("base ot sender party missing")
		}
		output, found := vsotRound2Output.Get(identity)
		if !found {
			return nil, errs.NewFailed("vsot round output missing")
		}
		baseOTP2PMsg, err := sender.Round3PadTransfer(output)
		if err != nil {
			return nil, errs.WrapFailed(err, "vsot as sender for identity %x", identity.PublicKey().ToAffineCompressed())
		}
		baseOTP2P.Put(identity, baseOTP2PMsg)
	}
	return baseOTP2P, nil
}

func (p *Participant) Round4(round3output *hashmap.HashMap[integration.IdentityKey, Round3P2P]) (*hashmap.HashMap[integration.IdentityKey, Round4P2P], error) {
	baseOTP2P := hashmap.NewHashMap[integration.IdentityKey, vsot.Round4P2P]()
	for identity, receiver := range p.BaseOTReceiverParties.GetMap() {
		output, found := round3output.Get(identity)
		if !found {
			return nil, errs.NewFailed("base ot p2p output missing")
		}
		challenge, err := receiver.Round4RespondToChallenge(output)
		if err != nil {
			return nil, errs.WrapFailed(err, "receiver round 4 vsot")
		}
		baseOTP2P.Put(identity, challenge)
	}
	return baseOTP2P, nil
}

func (p *Participant) Round5(round4output *hashmap.HashMap[integration.IdentityKey, Round4P2P]) (*hashmap.HashMap[integration.IdentityKey, Round5P2P], error) {
	baseOTP2P := hashmap.NewHashMap[integration.IdentityKey, vsot.Round5P2P]()
	for _, identity := range p.BaseOTSenderParties.Keys() {
		sender, found := p.BaseOTSenderParties.Get(identity)
		if !found {
			return nil, errs.NewFailed("base ot sender party missing")
		}
		output, found := round4output.Get(identity)
		if !found {
			return nil, errs.NewFailed("base ot p2p output missing")
		}
		baseOTP2PMsg, err := sender.Round5Verify(output)
		if err != nil {
			return nil, errs.WrapFailed(err, "vsot as sender for identity %x", identity.PublicKey().ToAffineCompressed())
		}
		baseOTP2P.Put(identity, baseOTP2PMsg)
	}
	return baseOTP2P, nil
}

func (p *Participant) Round6(round5output *hashmap.HashMap[integration.IdentityKey, Round5P2P]) (*dkls23.Shard, error) {
	for _, identity := range p.BaseOTReceiverParties.Keys() {
		receiver, found := p.BaseOTReceiverParties.Get(identity)
		if !found {
			return nil, errs.NewFailed("base ot receiver party missing")
		}
		output, found := round5output.Get(identity)
		if !found {
			return nil, errs.NewFailed("base ot p2p output missing")
		}
		if err := receiver.Round6Verify(output); err != nil {
			return nil, errs.WrapFailed(err, "vsot as receiver for indentity %x", identity.PublicKey().ToAffineCompressed())
		}
	}
	p.Shard.PairwiseBaseOTs = hashmap.NewHashMap[integration.IdentityKey, *dkls23.BaseOTConfig]()
	for _, identity := range p.GetCohortConfig().Participants {
		if identity.PublicKey().Equal(p.MyIdentityKey.PublicKey()) {
			continue
		}
		sender, found := p.BaseOTSenderParties.Get(identity)
		if !found {
			return nil, errs.NewFailed("base ot sender party missing")
		}
		receiver, found := p.BaseOTReceiverParties.Get(identity)
		if !found {
			return nil, errs.NewFailed("base ot receiver party missing")
		}
		p.Shard.PairwiseBaseOTs.Put(identity, &dkls23.BaseOTConfig{
			AsSender:   sender.Output,
			AsReceiver: receiver.Output,
		})
	}
	// by now, it's fully computed
	return p.Shard, nil
}
