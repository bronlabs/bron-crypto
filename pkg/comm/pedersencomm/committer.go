package pedersencomm

import (
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"io"
)

var _ comm.HomomorphicCommitter[Message, *Commitment, *Opening] = (*committer)(nil)

type committer struct {
	h    curves.Point
	prng io.Reader
	*homomorphicScheme
}

func NewCommitter(sessionId []byte, curve curves.Curve, prng io.Reader) (*committer, error) {
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}

	// Generate a random generator from the sessionId and SomethingUpMySleeve
	hBytes, err := hashing.HashChain(base.RandomOracleHashFunction, sessionId, nothingUpMySleeve)
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
		Witness: witness,
	}

	return commitment, opening, nil
}
