package pedersen

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

// Committer produces Pedersen commitments using the provided key.
type Committer[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	key *Key[E, S]
}

// Commit samples fresh randomness and commits to a message, returning the commitment and witness.
func (c *Committer[E, S]) Commit(message *Message[S], prng io.Reader) (*Commitment[E, S], *Witness[S], error) {
	if prng == nil {
		return nil, nil, errs.NewArgument("prng cannot be nil")
	}
	if message == nil {
		return nil, nil, errs.NewArgument("message cannot be nil")
	}

	group := algebra.StructureMustBeAs[algebra.PrimeGroup[E, S]](c.key.h.Structure())
	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](group.ScalarStructure())
	wv, err := field.Random(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "cannot generate random witness")
	}
	witness := &Witness[S]{v: wv}
	com, err := c.CommitWithWitness(message, witness)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot commit with witness")
	}
	return com, witness, nil
}

// CommitWithWitness commits to a message using caller-supplied witness randomness.
func (c *Committer[E, S]) CommitWithWitness(message *Message[S], witness *Witness[S]) (*Commitment[E, S], error) {
	if message == nil {
		return nil, errs.NewIsNil("message cannot be nil")
	}
	if witness == nil {
		return nil, errs.NewIsNil("witness cannot be nil")
	}

	// TODO: change to multiscalar op? (for two ops, we gain almost nothing)
	// Compute g^m * h^r
	v := c.key.g.ScalarOp(message.v).Op(c.key.h.ScalarOp(witness.v))
	return &Commitment[E, S]{v: v}, nil
}
