package rvole_softspoken

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/mpc/rvole"
)

// Round1 runs the random OT extension for ξ OTs with random choice bits β,
// expands the received outputs into Bob's rows and returns Bob's message
// together with b = ⟨g, β⟩.
func (bob *Bob[P, B, S]) Round1() (*Round1P2P[P, B, S], S, error) {
	var nilS S
	if bob.round != 1 {
		return nil, nilS, rvole.ErrRound.WithMessage("round 1 called in round %d", bob.round)
	}
	otOutput, otMessage, err := bob.receiver.Extend(bob.core.Suite().Xi())
	if err != nil {
		return nil, nilS, errs.Wrap(err).WithMessage("OT extension failed")
	}
	b, err := bob.core.Choose(otOutput.Choices(), otOutput.Messages())
	if err != nil {
		return nil, nilS, errs.Wrap(err).WithMessage("cannot choose rows")
	}
	bob.round += 2
	return &Round1P2P[P, B, S]{OT: otMessage}, b, nil
}

// Round2 validates a before any state advances, then
// completes the OT extension on Bob's message, which binds the columns
// and the check responses to the transcript before θ is derived, and runs
// Alice's multiplication step on the ξ output pairs. A failed OT consistency
// check is an identifiable abort attributed to Bob.
func (alice *Alice[P, B, S]) Round2(r1 *Round1P2P[P, B, S], a []S) (*Round2P2P[P, B, S], []S, error) {
	if alice.round != 2 {
		return nil, nil, rvole.ErrRound.WithMessage("round 2 called in round %d", alice.round)
	}
	if err := r1.Validate(alice, alice.core.CopartyID()); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid message")
	}
	if err := alice.core.ValidateInput(a); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid input")
	}
	otOutput, err := alice.sender.Extend(r1.OT)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("OT extension failed")
	}
	multiply, c, err := alice.core.Multiply(otOutput.Messages(), a)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot multiply")
	}
	alice.round += 2
	return &Round2P2P[P, B, S]{Multiply: multiply}, c, nil
}

// Round3 verifies Alice's message and returns Bob's output d. A failed check
// is an identifiable abort attributed to Alice.
func (bob *Bob[P, B, S]) Round3(r2 *Round2P2P[P, B, S]) ([]S, error) {
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
	bob.round += 2
	return d, nil
}
