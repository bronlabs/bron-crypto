package refresh

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/hjky"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

// Round1 runs the zero-sharing subprotocol to derive a refresh offset.
func (p *Participant[G, S]) Round1() (broadcast *Round1Broadcast[G, S], unicasts network.OutgoingUnicasts[*Round1P2P[G, S], *Participant[G, S]], err error) {
	if p.round != 1 {
		return nil, nil, ErrRound.WithMessage("expected round 1")
	}
	bc, uu, err := p.zeroParticipant.Round1()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to execute zero sharing Round1")
	}

	uOut := hashmap.NewComparable[sharing.ID, *Round1P2P[G, S]]()
	for id, m := range uu.Iter() {
		uOut.Put(id, &Round1P2P[G, S]{
			HjkyR1: m,
		})
	}
	bOut := &Round1Broadcast[G, S]{
		HjkyR1: bc,
	}
	p.round++
	return bOut, uOut.Freeze(), nil
}

// Round2 finishes the refresh by adding the zero-share to the existing shard.
func (p *Participant[G, S]) Round2(r2b network.RoundMessages[*Round1Broadcast[G, S], *Participant[G, S]], r2u network.RoundMessages[*Round1P2P[G, S], *Participant[G, S]]) (output *tsig.BaseShard[G, S], err error) {
	if p.round != 2 {
		return nil, ErrRound.WithMessage("expected round 2")
	}

	if errB := network.ValidateIncomingMessages(p, p.zeroParticipant.Context().OtherPartiesOrdered(), r2b); errB != nil {
		return nil, errs.Wrap(errB)
	}
	if errU := network.ValidateIncomingMessages(p, p.zeroParticipant.Context().OtherPartiesOrdered(), r2u); errU != nil {
		return nil, errs.Wrap(errU)
	}

	hjkyR2U := hashmap.NewComparable[sharing.ID, *hjky.Round1P2P[G, S]]()
	for id, m := range r2u.Iter() {
		hjkyR2U.Put(id, m.HjkyR1)
	}
	hjkyR2B := hashmap.NewComparable[sharing.ID, *hjky.Round1Broadcast[G, S]]()
	for id, m := range r2b.Iter() {
		hjkyR2B.Put(id, m.HjkyR1)
	}

	share, verification, err := p.zeroParticipant.Round2(hjkyR2B.Freeze(), hjkyR2U.Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to run round 2 of zero participant")
	}

	share = share.Add(p.shard.Share())
	verification = verification.Op(p.shard.VerificationVector())

	output, err = tsig.NewBaseShard(share, verification, p.shard.AccessStructure())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to build validated refreshed shard")
	}
	p.round++
	return output, nil
}
