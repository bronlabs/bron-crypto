package signing_softspoken

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/mpc/rvole/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

// Round1 commits to R_i = r_i·G and starts both base OTs of every pair: as
// base-OT sender in the sessions where it is Bob and as base-OT receiver, with
// random choice bits, where it is Alice.
func (c *Cosigner[P, B, S]) Round1() (*Round1Broadcast[P, B, S], network.OutgoingUnicasts[*Round1P2P[P, B, S], *Cosigner[P, B, S]], error) {
	if c.round != 1 {
		return nil, nil, ErrRound.WithMessage("round 1 called in round %d", c.round)
	}
	commitment, err := c.core.Commit()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot commit to R")
	}

	unicasts := hashmap.NewComparable[sharing.ID, *Round1P2P[P, B, S]]()
	for id := range c.core.Ctx().OtherPartiesOrdered() {
		senderMessage, err := c.baseOTSenders[id].Round1()
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run base-OT sender round 1 with %d", id)
		}
		choices := make(ot.Choices, baseOTCount/8)
		if _, err := io.ReadFull(c.core.Prng(), choices); err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot sample base-OT choices")
		}
		receiverMessage, err := c.baseOTReceivers[id].Round1(choices)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run base-OT receiver round 1 with %d", id)
		}
		unicasts.Put(id, &Round1P2P[P, B, S]{BaseOTSender: senderMessage, BaseOTReceiver: receiverMessage})
	}

	c.round++
	return &Round1Broadcast[P, B, S]{BigRCommitment: commitment}, unicasts.Freeze(), nil
}

// Round2 finishes both base OTs of every pair, builds the rVOLE participants
// on the pairwise sessions and sends Bob's rVOLE message, keeping χ_{i,j}.
func (c *Cosigner[P, B, S]) Round2(r1b network.RoundMessages[*Round1Broadcast[P, B, S], *Cosigner[P, B, S]], r1u network.RoundMessages[*Round1P2P[P, B, S], *Cosigner[P, B, S]]) (network.OutgoingUnicasts[*Round2P2P[P, B, S], *Cosigner[P, B, S]], error) {
	if c.round != 2 {
		return nil, ErrRound.WithMessage("round 2 called in round %d", c.round)
	}
	if err := network.ValidateIncomingMessages(c, c.core.Ctx().OtherPartiesOrdered(), r1b); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid broadcast input")
	}
	if err := network.ValidateIncomingMessages(c, c.core.Ctx().OtherPartiesOrdered(), r1u); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid p2p input")
	}

	unicasts := hashmap.NewComparable[sharing.ID, *Round2P2P[P, B, S]]()
	for id := range c.core.Ctx().OtherPartiesOrdered() {
		bIn, _ := r1b.Get(id)
		uIn, _ := r1u.Get(id)
		c.core.ReceiveCommitment(id, bIn.BigRCommitment)

		aliceBase, err := c.baseOTReceivers[id].Round2(uIn.BaseOTSender)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run base-OT receiver round 2 with %d", id)
		}
		c.alice[id], err = rvole_softspoken.NewAlice(c.aliceCtx[id], c.core.MulSuite(), aliceBase, c.core.Prng())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create rVOLE Alice with %d", id)
		}

		bobBase, err := c.baseOTSenders[id].Round2(uIn.BaseOTReceiver)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run base-OT sender round 2 with %d", id)
		}
		c.bob[id], err = rvole_softspoken.NewBob(c.bobCtx[id], c.core.MulSuite(), bobBase, c.core.Prng())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create rVOLE Bob with %d", id)
		}

		mulR1, chi, err := c.bob[id].Round1()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run rVOLE Bob round 1 with %d", id)
		}
		c.core.ReceiveChi(id, chi)
		unicasts.Put(id, &Round2P2P[P, B, S]{MulR1: mulR1})
	}

	c.round++
	return unicasts.Freeze(), nil
}

// Round3 derives the additive key share sk_i, answers every rVOLE as Alice
// with input (r_i, sk_i), opens R_i and sends pk_i, Γ^u, Γ^v and ψ.
func (c *Cosigner[P, B, S]) Round3(r2u network.RoundMessages[*Round2P2P[P, B, S], *Cosigner[P, B, S]]) (*Round3Broadcast[P, B, S], network.OutgoingUnicasts[*Round3P2P[P, B, S], *Cosigner[P, B, S]], error) {
	if c.round != 3 {
		return nil, nil, ErrRound.WithMessage("round 3 called in round %d", c.round)
	}
	if err := network.ValidateIncomingMessages(c, c.core.Ctx().OtherPartiesOrdered(), r2u); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid p2p input")
	}

	a, err := c.core.AliceInput()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot derive the rVOLE input")
	}
	unicasts := hashmap.NewComparable[sharing.ID, *Round3P2P[P, B, S]]()
	for id := range c.core.Ctx().OtherPartiesOrdered() {
		uIn, _ := r2u.Get(id)
		mulR2, cShare, err := c.alice[id].Round2(uIn.MulR1, a)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run rVOLE Alice round 2 with %d", id)
		}
		check, err := c.core.CheckValues(id, cShare)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot derive the check values for %d", id)
		}
		unicasts.Put(id, &Round3P2P[P, B, S]{MulR2: mulR2, GammaU: check.GammaU, GammaV: check.GammaV, Psi: check.Psi})
	}
	opening, err := c.core.Opening()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot open R")
	}

	c.round++
	return &Round3Broadcast[P, B, S]{BigR: opening.BigR, BigRWitness: opening.BigRWitness, Pk: opening.Pk}, unicasts.Freeze(), nil
}

// Round4 opens the counterparties' R_j, finishes every rVOLE as Bob, verifies
// the check equations and the public key, and returns the partial signature.
func (c *Cosigner[P, B, S]) Round4(r3b network.RoundMessages[*Round3Broadcast[P, B, S], *Cosigner[P, B, S]], r3u network.RoundMessages[*Round3P2P[P, B, S], *Cosigner[P, B, S]], message []byte) (*dkls23.PartialSignature[P, B, S], error) {
	if c.round != 4 {
		return nil, ErrRound.WithMessage("round 4 called in round %d", c.round)
	}
	if err := network.ValidateIncomingMessages(c, c.core.Ctx().OtherPartiesOrdered(), r3b); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid broadcast input")
	}
	if err := network.ValidateIncomingMessages(c, c.core.Ctx().OtherPartiesOrdered(), r3u); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid p2p input")
	}

	for id := range c.core.Ctx().OtherPartiesOrdered() {
		bIn, _ := r3b.Get(id)
		uIn, _ := r3u.Get(id)
		if err := c.core.ReceiveOpening(id, bIn.opening()); err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot open R of %d", id)
		}
		d, err := c.bob[id].Round3(uIn.MulR2)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run rVOLE Bob round 3 with %d", id)
		}
		if err := c.core.Verify(id, d, uIn.checkValues()); err != nil {
			return nil, errs.Wrap(err).WithMessage("check of %d failed", id)
		}
	}
	partialSignature, err := c.core.Finish(message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot finish signing")
	}

	c.round++
	return partialSignature, nil
}
