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
	for id := range p.ctx.OtherPartiesOrdered() {
		u := new(Round1P2P[P, B, S])
		var err error
		u.OtR1, err = p.baseOTSenders[id].Round1()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 1 of VSOT party")
		}
		r1u.Put(id, u)
	}

	p.round++
	return r1u.Freeze(), nil
}

// Round2 executes protocol round 2.
func (p *Participant[P, B, S]) Round2(r1u network.RoundMessages[*Round1P2P[P, B, S], *Participant[P, B, S]]) (network.RoundMessages[*Round2P2P[P, B, S], *Participant[P, B, S]], error) {
	if p.round != 2 {
		return nil, ErrRound.WithMessage("Running round %d but participant expected round %d", 2, p.round)
	}
	if err := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r1u); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid messages")
	}

	p.state.receiverSeeds = hashmap.NewComparable[sharing.ID, *vsot.ReceiverOutput]()
	r2u := hashmap.NewComparable[sharing.ID, *Round2P2P[P, B, S]]()
	for id := range p.ctx.OtherPartiesOrdered() {
		uOut := new(Round2P2P[P, B, S])
		uIn, _ := r1u.Get(id)

		choices := make([]byte, (softspoken.Kappa+7)/8)
		_, err := io.ReadFull(p.prng, choices)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot sample choices")
		}
		var seed *vsot.ReceiverOutput
		uOut.OtR2, seed, err = p.baseOTReceivers[id].Round2(uIn.OtR1, choices)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 2 of VSOT party")
		}
		p.state.receiverSeeds.Put(id, seed)
		r2u.Put(id, uOut)
	}

	p.round++
	return r2u.Freeze(), nil
}

// Round3 executes protocol round 3.
func (p *Participant[P, B, S]) Round3(r2u network.RoundMessages[*Round2P2P[P, B, S], *Participant[P, B, S]]) (network.RoundMessages[*Round3P2P[P, B, S], *Participant[P, B, S]], error) {
	if p.round != 3 {
		return nil, ErrRound.WithMessage("Running round %d but participant expected round %d", 3, p.round)
	}
	if err := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r2u); err != nil {
		return nil, errs.Wrap(err)
	}

	p.state.senderSeeds = hashmap.NewComparable[sharing.ID, *vsot.SenderOutput]()
	r3u := hashmap.NewComparable[sharing.ID, *Round3P2P[P, B, S]]()
	for id := range p.ctx.OtherPartiesOrdered() {
		uOut := new(Round3P2P[P, B, S])
		uIn, _ := r2u.Get(id)

		var err error
		var seed *vsot.SenderOutput
		uOut.OtR3, seed, err = p.baseOTSenders[id].Round3(uIn.OtR2)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 3 of VSOT party")
		}
		p.state.senderSeeds.Put(id, seed)
		r3u.Put(id, uOut)
	}

	p.round++
	return r3u.Freeze(), nil
}

// Round4 executes protocol round 4.
func (p *Participant[P, B, S]) Round4(r3u network.RoundMessages[*Round3P2P[P, B, S], *Participant[P, B, S]]) (network.RoundMessages[*Round4P2P[P, B, S], *Participant[P, B, S]], error) {
	if p.round != 4 {
		return nil, ErrRound.WithMessage("Running round %d but participant expected round %d", 4, p.round)
	}
	if err := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r3u); err != nil {
		return nil, errs.Wrap(err)
	}

	r4u := hashmap.NewComparable[sharing.ID, *Round4P2P[P, B, S]]()
	for id := range p.ctx.OtherPartiesOrdered() {
		uOut := new(Round4P2P[P, B, S])
		uIn, _ := r3u.Get(id)

		var err error
		uOut.OtR4, err = p.baseOTReceivers[id].Round4(uIn.OtR3)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 4 of VSOT party")
		}
		r4u.Put(id, uOut)
	}

	p.round++
	return r4u.Freeze(), nil
}

// Round5 executes protocol round 5.
func (p *Participant[P, B, S]) Round5(r4u network.RoundMessages[*Round4P2P[P, B, S], *Participant[P, B, S]]) (network.RoundMessages[*Round5P2P[P, B, S], *Participant[P, B, S]], error) {
	if p.round != 5 {
		return nil, ErrRound.WithMessage("Running round %d but participant expected round %d", 5, p.round)
	}
	if err := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r4u); err != nil {
		return nil, errs.Wrap(err)
	}

	r5u := hashmap.NewComparable[sharing.ID, *Round5P2P[P, B, S]]()
	for id := range p.ctx.OtherPartiesOrdered() {
		uOut := new(Round5P2P[P, B, S])
		uIn, _ := r4u.Get(id)

		var err error
		uOut.OtR5, err = p.baseOTSenders[id].Round5(uIn.OtR4)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 5 of VSOT part")
		}
		r5u.Put(id, uOut)
	}

	p.round++
	return r5u.Freeze(), nil
}

// Round6 executes protocol round 6.
func (p *Participant[P, B, S]) Round6(r5u network.RoundMessages[*Round5P2P[P, B, S], *Participant[P, B, S]]) (*dkls23.Shard[P, B, S], error) {
	if p.round != 6 {
		return nil, ErrRound.WithMessage("Running round %d but participant expected round %d", 6, p.round)
	}
	if err := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r5u); err != nil {
		return nil, errs.Wrap(err)
	}

	for id := range p.ctx.OtherPartiesOrdered() {
		uIn, _ := r5u.Get(id)
		err := p.baseOTReceivers[id].Round6(uIn.OtR5)
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
