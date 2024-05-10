package elgamalcomm

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

var _ comm.HomomorphicCommitter[Message, *Commitment, *Opening] = (*committer)(nil)

type committer struct {
	prng io.Reader
	h    curves.Point
	*homomorphicScheme
}

func NewCommitter(sessionId []byte, publicKey curves.Point, prng io.Reader) (*committer, error) { //nolint:revive // will be used by interface
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	if publicKey == nil {
		return nil, errs.NewIsNil("publicKey is nil")
	}

	hBlindByte, err := hashing.HashChain(base.RandomOracleHashFunction, sessionId, nothingUpMySleeve)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash sessionId")
	}

	curve := publicKey.Curve()
	hBlind, err := curve.Hash(hBlindByte)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash to curve for H")
	}

	h := publicKey.Add(hBlind)
	c := &committer{
		h:                 h,
		prng:              prng,
		homomorphicScheme: scheme,
	}

	return c, nil
}

func (c *committer) Commit(message Message) (*Commitment, *Opening, error) {
	if message == nil {
		return nil, nil, errs.NewIsNil("message")
	}

	witness, err := message.Curve().ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not draw a random scalar")
	}

	c1, c2, err := encrypt(c.h, message, witness)
	if err != nil {
		return nil, nil, errs.NewFailed("could not run Elgamal encryption")
	}

	commitment := &Commitment{
		c1: c1,
		c2: c2,
	}
	opening := &Opening{
		message: message,
		witness: witness,
	}

	return commitment, opening, nil
}
