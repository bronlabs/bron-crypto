package dkg

import (
	"encoding/hex"

	zeroSetup "github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/setup"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/bbot"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls24"
)

type Round1P2P struct {
	ZeroSampling *zeroSetup.Round1P2P
	BaseOTSender bbot.Round1P2P

	_ ds.Incomparable
}

type Round2P2P struct {
	ZeroSampling   *zeroSetup.Round2P2P
	BaseOTReceiver bbot.Round2P2P

	_ ds.Incomparable
}

func (p *Participant) Round1() (types.RoundMessages[*Round1P2P], error) {
	zeroSamplingP2P, err := p.ZeroSamplingParty.Round1()
	if err != nil {
		return nil, errs.WrapFailed(err, "zero sampling round 1 failed")
	}
	baseOtP2P := hashmap.NewHashableHashMap[types.IdentityKey, bbot.Round1P2P]()
	for pair := range p.BaseOTSenderParties.Iter() {
		identity := pair.Key
		party := pair.Value
		r1out, err := party.Round1()
		if err != nil {
			return nil, errs.WrapFailed(err, "BaseOT as sender for identity %x", hex.EncodeToString(identity.PublicKey().ToAffineCompressed()[:]))
		}
		baseOtP2P.Put(identity, r1out)
	}

	p2pOutput := types.NewRoundMessages[*Round1P2P]()
	for identity := range p.Protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		zeroSamplingMessage, exists := zeroSamplingP2P.Get(identity)
		if !exists {
			return nil, errs.NewMissing("do not have a zero sampling message for %x", identity.PublicKey())
		}
		baseOtMessage, exists := baseOtP2P.Get(identity)
		if !exists {
			return nil, errs.NewMissing("do not have a baseot message for %x", identity.PublicKey())
		}
		p2pOutput.Put(identity, &Round1P2P{
			ZeroSampling: zeroSamplingMessage,
			BaseOTSender: baseOtMessage,
		})
	}
	return p2pOutput, nil
}

func (p *Participant) Round2(round1outputP2P types.RoundMessages[*Round1P2P]) (types.RoundMessages[*Round2P2P], error) {
	zeroSamplingRound1Output := types.NewRoundMessages[*zeroSetup.Round1P2P]()
	baseOtRound1Output := types.NewRoundMessages[bbot.Round1P2P]()
	for pair := range round1outputP2P.Iter() {
		sender := pair.Key
		message := pair.Value
		baseOtRound1Output.Put(sender, message.BaseOTSender)
		zeroSamplingRound1Output.Put(sender, message.ZeroSampling)
	}

	zeroSamplingP2P, err := p.ZeroSamplingParty.Round2(zeroSamplingRound1Output)
	if err != nil {
		return nil, errs.WrapFailed(err, "zero sampling round 2 failed")
	}

	baseOTP2P := types.NewRoundMessages[bbot.Round2P2P]()
	for pair := range p.BaseOTReceiverParties.Iter() {
		identity := pair.Key
		party := pair.Value
		r2In, exists := baseOtRound1Output.Get(identity)
		if !exists {
			return nil, errs.NewMissing("did not have a message from %x", identity.PublicKey())
		}
		r2out, err := party.Round2(r2In)
		if err != nil {
			return nil, errs.WrapFailed(err, "base OT as receiver for identity %x", identity.PublicKey())
		}
		baseOTP2P.Put(identity, r2out)
	}
	p2pOutput := types.NewRoundMessages[*Round2P2P]()
	for identity := range p.Protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		zeroSamplingMessage, exists := zeroSamplingP2P.Get(identity)
		if !exists {
			return nil, errs.NewMissing("do not have a zero sampling message for %x", identity.PublicKey())
		}
		baseOtMessage, exists := baseOTP2P.Get(identity)
		if !exists {
			return nil, errs.NewMissing("do not have a baseot message for %x", identity.PublicKey())
		}
		p2pOutput.Put(identity, &Round2P2P{
			ZeroSampling:   zeroSamplingMessage,
			BaseOTReceiver: baseOtMessage,
		})
	}

	return p2pOutput, nil
}

func (p *Participant) Round3(round2outputP2P types.RoundMessages[*Round2P2P]) (*dkls24.Shard, error) {
	var err error
	baseOtRound2Output := types.NewRoundMessages[bbot.Round2P2P]()
	zeroSamplingRound2Output := types.NewRoundMessages[*zeroSetup.Round2P2P]()
	for pair := range round2outputP2P.Iter() {
		sender := pair.Key
		message := pair.Value
		baseOtRound2Output.Put(sender, message.BaseOTReceiver)
		zeroSamplingRound2Output.Put(sender, message.ZeroSampling)
	}

	pairwiseSeeds, err := p.ZeroSamplingParty.Round3(zeroSamplingRound2Output)
	if err != nil {
		return nil, errs.WrapFailed(err, "zero sampling round 3 failed")
	}
	for pair := range p.BaseOTSenderParties.Iter() {
		identity := pair.Key
		party := pair.Value
		message, exists := baseOtRound2Output.Get(identity)
		if !exists {
			return nil, errs.NewMissing("do not have a base ot message from %x", identity.PublicKey())
		}
		if err := party.Round3(message); err != nil {
			return nil, errs.WrapFailed(err, "base OT as sender for identity %x", identity.PublicKey())
		}
	}
	pairwiseBaseOTs := hashmap.NewHashableHashMap[types.IdentityKey, *dkls24.BaseOTConfig]()
	for identity := range p.Protocol.Participants().Iter() {
		if identity.Equal(p.IdentityKey()) {
			continue
		}
		sender, exists := p.BaseOTSenderParties.Get(identity)
		if !exists {
			return nil, errs.NewMissing("cannot get the sender party for %x", identity.PublicKey())
		}
		receiver, exists := p.BaseOTReceiverParties.Get(identity)
		if !exists {
			return nil, errs.NewMissing("cannot get the receiver party for %x", identity.PublicKey())
		}
		pairwiseBaseOTs.Put(identity, &dkls24.BaseOTConfig{
			AsSender:   sender.Output,
			AsReceiver: receiver.Output,
		})
	}

	shard := &dkls24.Shard{
		SigningKeyShare: p.MySigningKeyShare,
		PublicKeyShares: p.MyPartialPublicKeys,
		PairwiseSeeds:   pairwiseSeeds,
		PairwiseBaseOTs: pairwiseBaseOTs,
	}

	// by now, it's fully computed
	if err := shard.Validate(p.Protocol, p.IdentityKey()); err != nil {
		return nil, errs.WrapValidation(err, "resulting shard is invalid")
	}
	return shard, nil
}
