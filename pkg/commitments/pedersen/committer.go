package pedersen

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

// CommitterOption is a functional option for configuring committers.
type CommitterOption[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]] = func(*Committer[E, S]) error

// Committer produces Pedersen commitments using the provided key.
type Committer[E FiniteAbelianGroupElement[E, S], S algebra.RingElement[S]] struct {
	key                 *Key[E, S]
	witnessValueSampler func(prng io.Reader) (S, error)
	messageRangeCheck   func(message *Message[S]) error
	witnessRangeCheck   func(witness *Witness[S]) error
}

// Commit samples fresh randomness and commits to a message, returning the commitment and witness.
func (c *Committer[E, S]) Commit(message *Message[S], prng io.Reader) (*Commitment[E, S], *Witness[S], error) {
	if prng == nil {
		return nil, nil, ErrInvalidArgument.WithMessage("prng cannot be nil")
	}
	if err := c.messageRangeCheck(message); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid message")
	}

	wv, err := c.witnessValueSampler(prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot generate random witness")
	}
	witness, err := NewWitness(wv)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot construct witness")
	}
	com, err := c.CommitWithWitness(message, witness)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot commit with witness")
	}
	return com, witness, nil
}

// CommitWithWitness commits to a message using caller-supplied witness randomness.
func (c *Committer[E, S]) CommitWithWitness(message *Message[S], witness *Witness[S]) (*Commitment[E, S], error) {
	if message == nil {
		return nil, ErrInvalidArgument.WithMessage("message cannot be nil")
	}
	if err := c.witnessRangeCheck(witness); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid witness")
	}

	// Compute g^m * h^r
	v := c.key.g.ScalarOp(message.v).Op(c.key.h.ScalarOp(witness.v))
	return &Commitment[E, S]{v: v}, nil
}
