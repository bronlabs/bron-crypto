package signing_mrr21

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

// Round1 commits to R_i = r_i·G and sends both round-1 messages of every
// pair's rVOLEs: Alice's base-OT sender message where this party is Alice and
// Bob's POPFs on random choice bits where it is Bob.
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
		aliceR1, err := c.alice[id].Round1()
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run rVOLE Alice round 1 with %d", id)
		}
		bobR1, err := c.bob[id].Round1()
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run rVOLE Bob round 1 with %d", id)
		}
		unicasts.Put(id, &Round1P2P[P, B, S]{MulAliceR1: aliceR1, MulBobR1: bobR1})
	}

	c.round++
	return &Round1Broadcast[P, B, S]{BigRCommitment: commitment}, unicasts.Freeze(), nil
}

// Round2 completes every rVOLE as Bob, learning χ_{i,j}, derives the additive
// key share sk_i, answers every rVOLE as Alice with input (r_i, sk_i), opens
// R_i and sends pk_i, Γ^u, Γ^v and ψ.
func (c *Cosigner[P, B, S]) Round2(r1b network.RoundMessages[*Round1Broadcast[P, B, S], *Cosigner[P, B, S]], r1u network.RoundMessages[*Round1P2P[P, B, S], *Cosigner[P, B, S]]) (*Round2Broadcast[P, B, S], network.OutgoingUnicasts[*Round2P2P[P, B, S], *Cosigner[P, B, S]], error) {
	if c.round != 2 {
		return nil, nil, ErrRound.WithMessage("round 2 called in round %d", c.round)
	}
	if err := network.ValidateIncomingMessages(c, c.core.Ctx().OtherPartiesOrdered(), r1b); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid broadcast input")
	}
	if err := network.ValidateIncomingMessages(c, c.core.Ctx().OtherPartiesOrdered(), r1u); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid p2p input")
	}

	for id := range c.core.Ctx().OtherPartiesOrdered() {
		bIn, _ := r1b.Get(id)
		uIn, _ := r1u.Get(id)
		c.core.ReceiveCommitment(id, bIn.BigRCommitment)
		chi, err := c.bob[id].Round2(uIn.MulAliceR1)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run rVOLE Bob round 2 with %d", id)
		}
		c.core.ReceiveChi(id, chi)
	}

	a, err := c.core.AliceInput()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot derive the rVOLE input")
	}
	unicasts := hashmap.NewComparable[sharing.ID, *Round2P2P[P, B, S]]()
	for id := range c.core.Ctx().OtherPartiesOrdered() {
		uIn, _ := r1u.Get(id)
		mulR2, cShare, err := c.alice[id].Round2(uIn.MulBobR1, a)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run rVOLE Alice round 2 with %d", id)
		}
		check, err := c.core.CheckValues(id, cShare)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot derive the check values for %d", id)
		}
		unicasts.Put(id, &Round2P2P[P, B, S]{MulR2: mulR2, GammaU: check.GammaU, GammaV: check.GammaV, Psi: check.Psi})
	}
	opening, err := c.core.Opening()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot open R")
	}

	c.round++
	return &Round2Broadcast[P, B, S]{BigR: opening.BigR, BigRWitness: opening.BigRWitness, Pk: opening.Pk}, unicasts.Freeze(), nil
}

// Round3 opens the counterparties' R_j, finishes every rVOLE as Bob, verifies
// the check equations and the public key, and returns the partial signature.
func (c *Cosigner[P, B, S]) Round3(r2b network.RoundMessages[*Round2Broadcast[P, B, S], *Cosigner[P, B, S]], r2u network.RoundMessages[*Round2P2P[P, B, S], *Cosigner[P, B, S]], message []byte) (*dkls23.PartialSignature[P, B, S], error) {
	if c.round != 3 {
		return nil, ErrRound.WithMessage("round 3 called in round %d", c.round)
	}
	if err := network.ValidateIncomingMessages(c, c.core.Ctx().OtherPartiesOrdered(), r2b); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid broadcast input")
	}
	if err := network.ValidateIncomingMessages(c, c.core.Ctx().OtherPartiesOrdered(), r2u); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid p2p input")
	}

	for id := range c.core.Ctx().OtherPartiesOrdered() {
		bIn, _ := r2b.Get(id)
		uIn, _ := r2u.Get(id)
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
