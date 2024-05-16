package dkg

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/network"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot"
	zeroSetup "github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/rprzs/setup"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23"
)

func (p *Participant) Round1() (network.RoundMessages[types.ThresholdProtocol, *Round1P2P], error) {
	// Validation
	if p.Round != 1 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 1, p.Round)
	}

	zeroSamplingP2P, err := p.ZeroSamplingParty.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "zero sampling round 1 failed")
	}
	baseOtP2P := hashmap.NewHashableHashMap[types.IdentityKey, *bbot.Round1P2P]()
	for iterator := p.BaseOTSenderParties.Iterator(); iterator.HasNext(); {
		pair := iterator.Next()
		identity := pair.Key
		party := pair.Value
		r1out, err := party.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "BaseOT as sender for identity %s", identity.String())
		}
		baseOtP2P.Put(identity, r1out)
	}

	p2pOutput := network.NewRoundMessages[types.ThresholdProtocol, *Round1P2P]()
	for iterator := p.Protocol.Participants().Iterator(); iterator.HasNext(); {
		identity := iterator.Next()
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		zeroSamplingMessage, exists := zeroSamplingP2P.Get(identity)
		if !exists {
			return nil, errs.NewMissing("do not have a zero sampling message for %s", identity.String())
		}
		baseOtMessage, exists := baseOtP2P.Get(identity)
		if !exists {
			return nil, errs.NewMissing("do not have a baseot message for %s", identity.String())
		}
		p2pOutput.Put(identity, &Round1P2P{
			ZeroSampling: zeroSamplingMessage,
			BaseOTSender: baseOtMessage,
		})
	}

	p.Round++
	return p2pOutput, nil
}

func (p *Participant) Round2(round1outputP2P network.RoundMessages[types.ThresholdProtocol, *Round1P2P]) (network.RoundMessages[types.ThresholdProtocol, *Round2P2P], error) {
	// Validation
	if p.Round != 2 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 2, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), round1outputP2P); err != nil {
		return nil, errs.WrapValidation(err, "round 1 output is invalid")
	}

	zeroSamplingRound1Output := network.NewRoundMessages[types.Protocol, *zeroSetup.Round1P2P]()
	baseOtRound1Output := network.NewRoundMessages[types.Protocol, *bbot.Round1P2P]()
	for iterator := round1outputP2P.Iterator(); iterator.HasNext();{
		pair := iterator.Next()
		sender := pair.Key
		message := pair.Value
		baseOtRound1Output.Put(sender, message.BaseOTSender)
		zeroSamplingRound1Output.Put(sender, message.ZeroSampling)
	}

	zeroSamplingP2P, err := p.ZeroSamplingParty.Round2(zeroSamplingRound1Output)
	if err != nil {
		return nil, errs.WrapFailed(err, "zero sampling round 2 failed")
	}

	baseOTP2P := network.NewRoundMessages[types.Protocol, *bbot.Round2P2P]()
	for iterator := p.BaseOTReceiverParties.Iterator(); iterator.HasNext();{
		pair := iterator.Next()
		identity := pair.Key
		party := pair.Value
		r2In, exists := baseOtRound1Output.Get(identity)
		if !exists {
			return nil, errs.NewMissing("did not have a message from %s", identity.String())
		}
		r2out, err := party.Round2(r2In)
		if err != nil {
			return nil, errs.WrapFailed(err, "base OT as receiver for identity %s", identity.String())
		}
		baseOTP2P.Put(identity, r2out)
	}
	p2pOutput := network.NewRoundMessages[types.ThresholdProtocol, *Round2P2P]()
	for iterator := p.Protocol.Participants().Iterator(); iterator.HasNext(); {
		identity := iterator.Next()
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		zeroSamplingMessage, exists := zeroSamplingP2P.Get(identity)
		if !exists {
			return nil, errs.NewMissing("do not have a zero sampling message for %s", identity.String())
		}
		baseOtMessage, exists := baseOTP2P.Get(identity)
		if !exists {
			return nil, errs.NewMissing("do not have a baseot message for %s", identity.String())
		}
		p2pOutput.Put(identity, &Round2P2P{
			ZeroSampling:   zeroSamplingMessage,
			BaseOTReceiver: baseOtMessage,
		})
	}

	p.Round++
	return p2pOutput, nil
}

func (p *Participant) Round3(mySigningKeyShare *tsignatures.SigningKeyShare, round2outputP2P network.RoundMessages[types.ThresholdProtocol, *Round2P2P]) (shard *dkls23.Shard, err error) {
	// Validation
	if p.Round != 3 {
		return nil, errs.NewRound("Running round %d but participant expected round %d", 3, p.Round)
	}
	if err := network.ValidateMessages(p.Protocol, p.Protocol.Participants(), p.IdentityKey(), round2outputP2P); err != nil {
		return nil, errs.WrapValidation(err, "round 2 output is invalid")
	}
	if err := mySigningKeyShare.Validate(p.Protocol); err != nil {
		return nil, errs.WrapValidation(err, "signing key share is invalid")
	}

	baseOtRound2Output := network.NewRoundMessages[types.Protocol, *bbot.Round2P2P]()
	zeroSamplingRound2Output := network.NewRoundMessages[types.Protocol, *zeroSetup.Round2P2P]()

	for iterator := p.Protocol.Participants().Iterator(); iterator.HasNext(); {
		party := iterator.Next()
		if party.Equal(p.myAuthKey) {
			continue
		}
		message, _ := round2outputP2P.Get(party)
		baseOtRound2Output.Put(party, message.BaseOTReceiver)
		zeroSamplingRound2Output.Put(party, message.ZeroSampling)
	}

	pairwiseSeeds, err := p.ZeroSamplingParty.Round3(zeroSamplingRound2Output)
	if err != nil {
		return nil, errs.WrapFailed(err, "zero sampling round 3 failed")
	}

	for iterator := p.BaseOTSenderParties.Iterator(); iterator.HasNext(); {
		pair := iterator.Next()
		identity := pair.Key
		party := pair.Value
		message, _ := baseOtRound2Output.Get(identity)
		if err := party.Round3(message); err != nil {
			return nil, errs.WrapFailed(err, "base OT as sender for identity %s", identity.String())
		}
	}
	pairwiseBaseOTs := hashmap.NewHashableHashMap[types.IdentityKey, *dkls23.BaseOTConfig]()
	for iterator := p.Protocol.Participants().Iterator(); iterator.HasNext(); {
		identity := iterator.Next()
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		sender, exists := p.BaseOTSenderParties.Get(identity)
		if !exists {
			return nil, errs.NewMissing("cannot get the sender party for %s", identity.String())
		}
		receiver, exists := p.BaseOTReceiverParties.Get(identity)
		if !exists {
			return nil, errs.NewMissing("cannot get the receiver party for %s", identity.String())
		}
		pairwiseBaseOTs.Put(identity, &dkls23.BaseOTConfig{
			AsSender:   sender.Output,
			AsReceiver: receiver.Output,
		})
	}

	shard = &dkls23.Shard{
		SigningKeyShare: mySigningKeyShare,
		PublicKeyShares: p.MyPartialPublicKeys,
		PairwiseSeeds:   pairwiseSeeds,
		PairwiseBaseOTs: pairwiseBaseOTs,
	}

	// by now, it's fully computed
	if err := shard.Validate(p.Protocol, p.IdentityKey()); err != nil {
		return nil, errs.WrapValidation(err, "resulting shard is invalid")
	}

	p.Round++
	return shard, nil
}
