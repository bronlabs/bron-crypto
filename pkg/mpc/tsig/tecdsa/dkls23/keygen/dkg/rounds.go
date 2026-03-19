package dkg

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/vsot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
	"github.com/bronlabs/errs-go/errs"
)

// Round1 executes protocol round 1.
func (p *Participant[P, B, S]) Round1() (network.OutgoingUnicasts[*Round1P2P[P, B, S], *Participant[P, B, S]], error) {
	r1u := hashmap.NewComparable[sharing.ID, *Round1P2P[P, B, S]]()
	for id, u := range outgoingP2PMessages(p, r1u) {
		var err error
		u.OtR1, err = p.baseOTSenders[id].Round1()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 1 of VSOT party")
		}
	}

	p.round++
	return r1u.Freeze(), nil
}

// Round2 executes protocol round 2.
func (p *Participant[P, B, S]) Round2(r1u network.RoundMessages[*Round1P2P[P, B, S], *Participant[P, B, S]]) (network.RoundMessages[*Round2P2P[P, B, S], *Participant[P, B, S]], error) {
	otR1 := hashmap.NewComparable[sharing.ID, *vsot.Round1P2P[P, B, S]]()
	in, err := incomingP2PMessages(p, 2, r1u)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid messages or round mismatch")
	}
	for id, m := range in {
		otR1.Put(id, m.OtR1)
	}

	p.state.receiverSeeds = hashmap.NewComparable[sharing.ID, *vsot.ReceiverOutput]()
	r2u := hashmap.NewComparable[sharing.ID, *Round2P2P[P, B, S]]()
	for id, u := range outgoingP2PMessages(p, r2u) {
		var ok bool
		var err error
		var seed *vsot.ReceiverOutput

		otR1u, ok := otR1.Get(id)
		if !ok {
			return nil, ErrFailed.WithMessage("cannot run round 2 of VSOT setup party")
		}
		choices := make([]byte, (softspoken.Kappa+7)/8)
		_, err = io.ReadFull(p.prng, choices)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot sample choices")
		}
		u.OtR2, seed, err = p.baseOTReceivers[id].Round2(otR1u, choices)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 2 of VSOT party")
		}
		p.state.receiverSeeds.Put(id, seed)
	}

	p.round++
	return r2u.Freeze(), nil
}

// Round3 executes protocol round 3.
func (p *Participant[P, B, S]) Round3(r2u network.RoundMessages[*Round2P2P[P, B, S], *Participant[P, B, S]]) (network.RoundMessages[*Round3P2P[P, B, S], *Participant[P, B, S]], error) {
	otR2u := hashmap.NewComparable[sharing.ID, *vsot.Round2P2P[P, B, S]]()
	in, err := incomingP2PMessages(p, 3, r2u)
	if err != nil {
		return nil, ErrFailed.WithMessage("invalid messages or round mismatch")
	}
	for id, m := range in {
		otR2u.Put(id, m.OtR2)
	}

	p.state.senderSeeds = hashmap.NewComparable[sharing.ID, *vsot.SenderOutput]()
	r3u := hashmap.NewComparable[sharing.ID, *Round3P2P[P, B, S]]()
	for id, u := range outgoingP2PMessages(p, r3u) {
		otR2, ok := otR2u.Get(id)
		if !ok {
			return nil, ErrFailed.WithMessage("cannot run round 3 of VSOT party")
		}
		var seed *vsot.SenderOutput
		u.OtR3, seed, err = p.baseOTSenders[id].Round3(otR2)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 3 of VSOT party")
		}
		p.state.senderSeeds.Put(id, seed)
	}

	p.round++
	return r3u.Freeze(), nil
}

// Round4 executes protocol round 4.
func (p *Participant[P, B, S]) Round4(r3u network.RoundMessages[*Round3P2P[P, B, S], *Participant[P, B, S]]) (network.RoundMessages[*Round4P2P[P, B, S], *Participant[P, B, S]], error) {
	otR3u := hashmap.NewComparable[sharing.ID, *vsot.Round3P2P[P, B, S]]()
	in, err := incomingP2PMessages(p, 4, r3u)
	if err != nil {
		return nil, ErrFailed.WithMessage("invalid messages or round mismatch")
	}
	for id, p2p := range in {
		otR3u.Put(id, p2p.OtR3)
	}

	r4u := hashmap.NewComparable[sharing.ID, *Round4P2P[P, B, S]]()
	for id, u := range outgoingP2PMessages(p, r4u) {
		otR3, ok := otR3u.Get(id)
		if !ok {
			return nil, ErrFailed.WithMessage("cannot run round 4 of VSOT party")
		}
		var err error
		u.OtR4, err = p.baseOTReceivers[id].Round4(otR3)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 4 of VSOT party")
		}
	}

	p.round++
	return r4u.Freeze(), nil
}

// Round5 executes protocol round 5.
func (p *Participant[P, B, S]) Round5(r4u network.RoundMessages[*Round4P2P[P, B, S], *Participant[P, B, S]]) (network.RoundMessages[*Round5P2P[P, B, S], *Participant[P, B, S]], error) {
	otR4u := hashmap.NewComparable[sharing.ID, *vsot.Round4P2P[P, B, S]]()
	in, err := incomingP2PMessages(p, 5, r4u)
	if err != nil {
		return nil, ErrFailed.WithMessage("invalid messages or round mismatch")
	}
	for id, p2p := range in {
		otR4u.Put(id, p2p.OtR4)
	}

	r5u := hashmap.NewComparable[sharing.ID, *Round5P2P[P, B, S]]()
	for id, u := range outgoingP2PMessages(p, r5u) {
		otR4, ok := otR4u.Get(id)
		if !ok {
			return nil, ErrFailed.WithMessage("cannot run round 5 of VSOT party")
		}
		var err error
		u.OtR5, err = p.baseOTSenders[id].Round5(otR4)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 5 of VSOT part")
		}
	}

	p.round++
	return r5u.Freeze(), nil
}

// Round6 executes protocol round 6.
func (p *Participant[P, B, S]) Round6(r5u network.RoundMessages[*Round5P2P[P, B, S], *Participant[P, B, S]]) (*dkls23.Shard[P, B, S], error) {
	in, err := incomingP2PMessages(p, 6, r5u)
	if err != nil {
		return nil, ErrFailed.WithMessage("invalid messages or round mismatch")
	}
	for id, p2p := range in {
		err := p.baseOTReceivers[id].Round6(p2p.OtR5)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 6 of VSOT party")
		}
	}

	auxInfo, err := dkls23.NewAuxiliaryInfo(p.state.senderSeeds.Freeze(), p.state.receiverSeeds.Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create auxiliary info")
	}
	shard, err := dkls23.NewShard(p.baseShard, auxInfo)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create tECDSA DKLSS23 shard")
	}

	p.round++
	return shard, nil
}
