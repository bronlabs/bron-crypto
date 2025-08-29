package dkg

import (
	"io"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/threshold/dkg/gennaro"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	przsSetup "github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/przs/setup"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa"
)

func (p *Participant[P, B, S]) Round1() (*Round1Broadcast[P, B, S], ds.Map[sharing.ID, *Round1P2P[P, B, S]], error) {
	gennaroR1b, err := p.gennaroParty.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run round 1 of Gennaro DKG party")
	}
	zeroR1b, err := p.zeroSetup.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run round 1 of Gennaro DKG party")
	}

	r1b := &Round1Broadcast[P, B, S]{
		gennaroR1: gennaroR1b,
		zeroR1:    zeroR1b,
	}
	r1u := hashmap.NewComparable[sharing.ID, *Round1P2P[P, B, S]]()
	for id, u := range outgoingP2PMessages(p, r1u) {
		var err error
		u.otR1, err = p.baseOTSenders[id].Round1()
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot run round 1 of VSOT party")
		}
	}

	return r1b, r1u.Freeze(), nil
}

func (p *Participant[P, B, S]) Round2(r1b network.RoundMessages[*Round1Broadcast[P, B, S]], r1u network.RoundMessages[*Round1P2P[P, B, S]]) (*Round2Broadcast[P, B, S], network.RoundMessages[*Round2P2P[P, B, S]], error) {
	gennaroR1 := hashmap.NewComparable[sharing.ID, *gennaro.Round1Broadcast[P, S]]()
	zeroR1 := hashmap.NewComparable[sharing.ID, *przsSetup.Round1Broadcast]()
	otR1 := hashmap.NewComparable[sharing.ID, *vsot.Round1P2P[P, B, S]]()
	for id, m := range incomingMessages(p, 2, r1b, r1u) {
		gennaroR1.Put(id, m.broadcast.gennaroR1)
		zeroR1.Put(id, m.broadcast.zeroR1)
		otR1.Put(id, m.p2p.otR1)
	}

	gennaroR2b, gennaroR2u, err := p.gennaroParty.Round2(gennaroR1.Freeze())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run round 2 of Gennaro DKG party")
	}
	zeroR2u, err := p.zeroSetup.Round2(zeroR1.Freeze())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot run round 2 of PRZS setup party")
	}
	choices := make([]byte, (softspoken.Kappa+7)/8)
	_, err = io.ReadFull(p.prng, choices)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot sample choices")
	}

	p.state.receiverSeeds = hashmap.NewComparable[sharing.ID, *vsot.ReceiverOutput]()
	r2b := &Round2Broadcast[P, B, S]{
		gennaroR2: gennaroR2b,
	}
	r2u := hashmap.NewComparable[sharing.ID, *Round2P2P[P, B, S]]()
	for id, u := range outgoingP2PMessages(p, r2u) {
		var ok bool
		var err error
		var seed *vsot.ReceiverOutput

		u.gennaroR2, ok = gennaroR2u.Get(id)
		if !ok {
			return nil, nil, errs.NewFailed("cannot run round 2 of Gennaro DKG party")
		}
		u.zeroR2, ok = zeroR2u.Get(id)
		if !ok {
			return nil, nil, errs.NewFailed("cannot run round 2 of PRZS setup party")
		}
		otR1u, ok := otR1.Get(id)
		if !ok {
			return nil, nil, errs.NewFailed("cannot run round 2 of VSOT setup party")
		}
		u.otR2, seed, err = p.baseOTReceivers[id].Round2(otR1u, choices)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "cannot run round 2 of VSOT party")
		}
		p.state.receiverSeeds.Put(id, seed)
	}

	return r2b, r2u.Freeze(), nil
}

func (p *Participant[P, B, S]) Round3(r2b network.RoundMessages[*Round2Broadcast[P, B, S]], r2u network.RoundMessages[*Round2P2P[P, B, S]]) (network.RoundMessages[*Round3P2P], error) {
	gennaroR2b := hashmap.NewComparable[sharing.ID, *gennaro.Round2Broadcast[P, S]]()
	gennaroR2u := hashmap.NewComparable[sharing.ID, *gennaro.Round2Unicast[P, S]]()
	zeroR2u := hashmap.NewComparable[sharing.ID, *przsSetup.Round2P2P]()
	otR2u := hashmap.NewComparable[sharing.ID, *vsot.Round2P2P[P, B, S]]()
	for id, m := range incomingMessages(p, 2, r2b, r2u) {
		gennaroR2b.Put(id, m.broadcast.gennaroR2)
		gennaroR2u.Put(id, m.p2p.gennaroR2)
		zeroR2u.Put(id, m.p2p.zeroR2)
		otR2u.Put(id, m.p2p.otR2)
	}

	var err error
	p.state.dkgOutput, err = p.gennaroParty.Round3(gennaroR2b.Freeze(), gennaroR2u.Freeze())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 3 of Gennaro DKG party")
	}
	p.state.zeroSeeds, err = p.zeroSetup.Round3(zeroR2u.Freeze())
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot run round 3 of PRZS setup party")
	}

	p.state.senderSeeds = hashmap.NewComparable[sharing.ID, *vsot.SenderOutput]()
	r3u := hashmap.NewComparable[sharing.ID, *Round3P2P]()
	for id, u := range outgoingP2PMessages(p, r3u) {
		otR2, ok := otR2u.Get(id)
		if !ok {
			return nil, errs.NewFailed("cannot run round 3 of VSOT party")
		}
		var seed *vsot.SenderOutput
		u.otR3, seed, err = p.baseOTSenders[id].Round3(otR2)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 3 of VSOT party")
		}
		p.state.senderSeeds.Put(id, seed)
	}

	return r3u.Freeze(), nil
}

func (p *Participant[P, B, S]) Round4(r3u network.RoundMessages[*Round3P2P]) (network.RoundMessages[*Round4P2P], error) {
	otR3u := hashmap.NewComparable[sharing.ID, *vsot.Round3P2P]()
	for id, p2p := range incomingP2PMessages(p, 4, r3u) {
		otR3u.Put(id, p2p.otR3)
	}

	r4u := hashmap.NewComparable[sharing.ID, *Round4P2P]()
	for id, u := range outgoingP2PMessages(p, r4u) {
		otR3, ok := otR3u.Get(id)
		if !ok {
			return nil, errs.NewFailed("cannot run round 4 of VSOT party")
		}
		var err error
		u.otR4, err = p.baseOTReceivers[id].Round4(otR3)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 4 of VSOT party")
		}
	}

	return r4u.Freeze(), nil
}

func (p *Participant[P, B, S]) Round5(r4u network.RoundMessages[*Round4P2P]) (network.RoundMessages[*Round5P2P], error) {
	otR4u := hashmap.NewComparable[sharing.ID, *vsot.Round4P2P]()
	for id, p2p := range incomingP2PMessages(p, 5, r4u) {
		otR4u.Put(id, p2p.otR4)
	}

	r5u := hashmap.NewComparable[sharing.ID, *Round5P2P]()
	for id, u := range outgoingP2PMessages(p, r5u) {
		otR4, ok := otR4u.Get(id)
		if !ok {
			return nil, errs.NewFailed("cannot run round 5 of VSOT party")
		}
		var err error
		u.otR5, err = p.baseOTSenders[id].Round5(otR4)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 5 of VSOT part")
		}
	}

	return r5u.Freeze(), nil
}

func (p *Participant[P, B, S]) Round6(r5u network.RoundMessages[*Round5P2P]) (*tecdsa.Shard[P, B, S], error) {
	for id, p2p := range incomingP2PMessages(p, 6, r5u) {
		err := p.baseOTReceivers[id].Round6(p2p.otR5)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot run round 6 of VSOT party")
		}
	}

	shard := tecdsa.NewShard(
		p.state.dkgOutput.Share(),
		p.state.dkgOutput.PublicMaterial().PublicKeyValue(),
		p.state.zeroSeeds,
		p.state.senderSeeds.Freeze(),
		p.state.receiverSeeds.Freeze(),
	)
	return shard, nil
}
