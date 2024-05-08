package hashcomm

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

var _ comm.Committer[Message, *Commitment, *Opening] = (*committer)(nil)

type committer struct {
	sessionId []byte
	prng      io.Reader
}

func NewCommitter(sessionId []byte, prng io.Reader) (*committer, error) { //nolint:revive // will be used by interface
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}

	c := &committer{
		sessionId: sessionId,
		prng:      prng,
	}
	return c, nil
}

func (c *committer) Commit(message Message) (*Commitment, *Opening, error) {
	if message == nil {
		return nil, nil, errs.NewIsNil("message")
	}

	witness := make([]byte, base.CollisionResistanceBytes)
	if _, err := io.ReadFull(c.prng, witness); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "reading random bytes")
	}

	commitmentValue, err := hashing.Hmac(witness, hashFunc, encodeSessionId(c.sessionId), message)
	if err != nil {
		return nil, nil, errs.WrapHashing(err, "could not compute commitment")
	}

	commitment := &Commitment{
		value: commitmentValue,
	}
	opening := &Opening{
		message: message,
		witness: witness,
	}
	return commitment, opening, nil
}
