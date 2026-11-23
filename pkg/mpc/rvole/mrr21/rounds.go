package rvole_mrr21

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/mpc/rvole"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

// Round1 sends Alice's base-OT message m_S. It does not depend on Bob's, so
// both round-1 messages travel at once.
func (alice *Alice[P, B, S]) Round1() (*AliceRound1P2P[P, B, S], error) {
	if alice.round != 1 {
		return nil, rvole.ErrRound.WithMessage("round 1 called in round %d", alice.round)
	}
	otMessage, err := alice.sender.Round1()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("base-OT round 1 failed")
	}
	alice.round++
	return &AliceRound1P2P[P, B, S]{OT: otMessage}, nil
}

// Round1 samples Bob's ξ choice bits β and sends his base-OT message, the
// POPFs programmed on them.
func (bob *Bob[P, B, S]) Round1() (*BobRound1P2P[P, B, S], error) {
	if bob.round != 1 {
		return nil, rvole.ErrRound.WithMessage("round 1 called in round %d", bob.round)
	}
	beta := make(ot.Choices, bob.core.Suite().Xi()/8)
	if _, err := io.ReadFull(bob.prng, beta); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot sample choice bits")
	}
	otMessage, err := bob.receiver.Round1(beta)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("base-OT round 1 failed")
	}
	bob.round++
	return &BobRound1P2P[P, B, S]{OT: otMessage}, nil
}

// Round2 completes Bob's base OTs on Alice's message, expands the received
// outputs into his rows and returns b = ⟨g, β⟩.
func (bob *Bob[P, B, S]) Round2(r1 *AliceRound1P2P[P, B, S]) (S, error) {
	var nilS S
	if bob.round != 2 {
		return nilS, rvole.ErrRound.WithMessage("round 2 called in round %d", bob.round)
	}
	if err := r1.Validate(bob, bob.core.CopartyID()); err != nil {
		return nilS, errs.Wrap(err).WithMessage("invalid message")
	}
	otOutput, err := bob.receiver.Round2(r1.OT)
	if err != nil {
		return nilS, errs.Wrap(err).WithMessage("base-OT round 2 failed")
	}
	b, err := bob.core.Choose(otOutput.Choices(), otOutput.Messages())
	if err != nil {
		return nilS, errs.Wrap(err).WithMessage("cannot choose rows")
	}
	bob.round++
	return b, nil
}

// Round2 checks a has exactly ℓ entries before any state advances, then
// completes Alice's base OTs on Bob's message, which binds m_S and the
// POPFs to the transcript before θ is derived, and runs her multiplication
// step on the ξ output pairs. A malformed POPF is an identifiable abort
// attributed to Bob.
func (alice *Alice[P, B, S]) Round2(r1 *BobRound1P2P[P, B, S], a []S) (*AliceRound2P2P[P, B, S], []S, error) {
	if alice.round != 2 {
		return nil, nil, rvole.ErrRound.WithMessage("round 2 called in round %d", alice.round)
	}
	if err := r1.Validate(alice, alice.core.CopartyID()); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid message")
	}
	if l := alice.core.Suite().L(); len(a) != l {
		return nil, nil, rvole.ErrInvalidArgument.WithMessage("%d inputs, expected %d", len(a), l)
	}
	otOutput, err := alice.sender.Round2(r1.OT)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("base-OT round 2 failed")
	}
	multiply, c, err := alice.core.Multiply(otOutput.Messages(), a)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot multiply")
	}
	alice.round++
	return &AliceRound2P2P[P, B, S]{Multiply: multiply}, c, nil
}

// Round3 verifies Alice's message and returns Bob's output d. A failed check
// is an identifiable abort attributed to Alice.
func (bob *Bob[P, B, S]) Round3(r2 *AliceRound2P2P[P, B, S]) ([]S, error) {
	if bob.round != 3 {
		return nil, rvole.ErrRound.WithMessage("round 3 called in round %d", bob.round)
	}
	if err := r2.Validate(bob, bob.core.CopartyID()); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid message")
	}
	d, err := bob.core.Finish(r2.Multiply)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot finish")
	}
	bob.round++
	return d, nil
}
