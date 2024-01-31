package dkg

import (
	"encoding/hex"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
)

type Round1Broadcast = gennaro.Round1Broadcast
type Round1P2P struct {
	Gennaro    *gennaro.Round1P2P
	VSOTSender *vsot.Round1P2P

	_ types.Incomparable
}

type Round2Broadcast = gennaro.Round2Broadcast
type Round2P2P struct {
	VSOTReceiver vsot.Round2P2P

	_ types.Incomparable
}

// Acting as sender.
type Round3P2P = vsot.Round3P2P

// Acting as receiver.
type Round4P2P = vsot.Round4P2P

// Acting as sender.
type Round5P2P = vsot.Round5P2P

func (p *Participant) Round1() (*Round1Broadcast, map[types.IdentityHash]*Round1P2P, error) {
	gennaroBroadcast, gennaroP2P, err := p.GennaroParty.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "gennaro round 1 failed")
	}
	baseOTP2P := map[types.IdentityHash]*vsot.Round1P2P{}
	for identity, party := range p.BaseOTSenderParties {
		proof, publicKey, err := party.Round1ComputeAndZkpToPublicKey()
		baseOTP2P[identity] = &vsot.Round1P2P{
			Proof:     proof,
			PublicKey: publicKey,
		}
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "vsot as sender for identity %x", hex.EncodeToString(identity[:]))
		}
	}

	p2pOutput := make(map[types.IdentityHash]*Round1P2P, len(gennaroP2P))

	for identity, message := range gennaroP2P {
		p2pOutput[identity] = &Round1P2P{
			Gennaro:    message,
			VSOTSender: baseOTP2P[identity],
		}
	}
	return gennaroBroadcast, p2pOutput, nil
}

func (p *Participant) Round2(round1outputBroadcast map[types.IdentityHash]*Round1Broadcast, round1outputP2P map[types.IdentityHash]*Round1P2P) (*Round2Broadcast, map[types.IdentityHash]*Round2P2P, error) {
	gennaroRound1outputP2P := map[types.IdentityHash]*gennaro.Round1P2P{}
	vsotRound1Output := map[types.IdentityHash]*vsot.Round1P2P{}
	for identity, message := range round1outputP2P {
		gennaroRound1outputP2P[identity] = message.Gennaro
		vsotRound1Output[identity] = message.VSOTSender
	}
	gennaroBroadcast, err := p.GennaroParty.Round2(round1outputBroadcast, gennaroRound1outputP2P)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "gennaro round 2 failed")
	}

	baseOTP2P := map[types.IdentityHash]vsot.Round2P2P{}
	for identity, receiver := range p.BaseOTReceiverParties {
		baseOTP2P[identity], err = receiver.Round2VerifySchnorrAndPadTransfer(vsotRound1Output[identity].PublicKey, vsotRound1Output[identity].Proof)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "vsot as receiver for identity %x", hex.EncodeToString(identity[:]))
		}
	}
	p2pOutput := make(map[types.IdentityHash]*Round2P2P, len(baseOTP2P))
	for identity := range baseOTP2P {
		p2pOutput[identity] = &Round2P2P{
			VSOTReceiver: baseOTP2P[identity],
		}
	}

	return gennaroBroadcast, p2pOutput, nil
}

func (p *Participant) Round3(round2outputBroadcast map[types.IdentityHash]*Round2Broadcast, round2outputP2P map[types.IdentityHash]*Round2P2P) (map[types.IdentityHash]Round3P2P, error) {
	vsotRound2Output := map[types.IdentityHash]vsot.Round2P2P{}
	for identity, message := range round2outputP2P {
		vsotRound2Output[identity] = message.VSOTReceiver
	}
	var err error
	p.Shard.SigningKeyShare, p.Shard.PublicKeyShares, err = p.GennaroParty.Round3(round2outputBroadcast)
	if err != nil {
		return nil, errs.WrapFailed(err, "gennaro round 3 failed")
	}

	baseOTP2P := map[types.IdentityHash]vsot.Round3P2P{}
	for identity, sender := range p.BaseOTSenderParties {
		baseOTP2P[identity], err = sender.Round3PadTransfer(vsotRound2Output[identity])
		if err != nil {
			return nil, errs.WrapFailed(err, "vsot as sender for identity %x", hex.EncodeToString(identity[:]))
		}
	}
	return baseOTP2P, nil
}

func (p *Participant) Round4(round3output map[types.IdentityHash]Round3P2P) (map[types.IdentityHash]Round4P2P, error) {
	var err error
	baseOTP2P := map[types.IdentityHash]vsot.Round4P2P{}
	for identity, receiver := range p.BaseOTReceiverParties {
		baseOTP2P[identity], err = receiver.Round4RespondToChallenge(round3output[identity])
		if err != nil {
			return nil, errs.WrapFailed(err, "receiver round 4 vsot")
		}
	}
	return baseOTP2P, nil
}

func (p *Participant) Round5(round4output map[types.IdentityHash]Round4P2P) (map[types.IdentityHash]Round5P2P, error) {
	var err error
	baseOTP2P := map[types.IdentityHash]vsot.Round5P2P{}
	for identity, sender := range p.BaseOTSenderParties {
		baseOTP2P[identity], err = sender.Round5Verify(round4output[identity])
		if err != nil {
			return nil, errs.WrapFailed(err, "vsot as sender for identity %x", hex.EncodeToString(identity[:]))
		}
	}
	return baseOTP2P, nil
}

func (p *Participant) Round6(round5output map[types.IdentityHash]Round5P2P) (*dkls24.Shard, error) {
	for identity, receiver := range p.BaseOTReceiverParties {
		if err := receiver.Round6Verify(round5output[identity]); err != nil {
			return nil, errs.WrapFailed(err, "vsot as receiver for indentity %x", hex.EncodeToString(identity[:]))
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
