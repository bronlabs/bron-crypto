package pedersencommitments

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

var _ commitments.HomomorphicCommitter[Message, *Commitment, *Opening] = (*committer)(nil)

type committer struct {
	h    curves.Point
	prng io.Reader
	*homomorphicScheme
}

func NewCommitter(sessionId []byte, curve curves.Curve, prng io.Reader) (*committer, error) { //nolint:revive // will be used by interface
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}

	hBytes, err := hashing.HashChain(base.RandomOracleHashFunction, nothingUpMySleeve)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash chain")
	}

	h, err := curve.Hash(hBytes)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash to curve for H")
	}

	return &committer{
		h:                 h,
		prng:              prng,
		homomorphicScheme: scheme,
	}, nil
}

func (c *committer) Commit(message Message) (*Commitment, *Opening, error) {
	if message == nil {
		return nil, nil, errs.NewIsNil("message")
	}

	curve := message.ScalarField().Curve()
	witness, err := message.ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSample(err, "generating random scalar")
	}

	mG := curve.Generator().ScalarMul(message)
	rH := c.h.ScalarMul(witness)

	commitment := &Commitment{
		value: rH.Add(mG),
	}
	opening := &Opening{
		message: message,
		witness: witness,
	}

	return commitment, opening, nil
}
