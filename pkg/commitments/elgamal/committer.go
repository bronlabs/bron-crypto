package elgamalcommitments

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
)

var _ commitments.HomomorphicCommitter[Message, *Commitment, *Opening] = (*committer)(nil)

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

	hBlindBytes, err := hashing.HashPrefixedLength(base.RandomOracleHashFunction, sessionId, nothingUpMySleeve)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash sessionId")
	}

	curve := publicKey.Curve()
	hBlind, err := curve.Hash(hBlindBytes)
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
		C1: c1,
		C2: c2,
	}
	opening := &Opening{
		Message: message,
		Witness: witness,
	}

	return commitment, opening, nil
}
