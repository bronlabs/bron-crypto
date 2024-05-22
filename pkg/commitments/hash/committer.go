package hashcommitments

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
)

var _ commitments.Committer[Message, *Commitment, *Opening] = (*Committer)(nil)

type Committer struct {
	sessionId []byte
	prefix    []byte
	prng      io.Reader
}

func NewCommitter(sessionId []byte, prng io.Reader, prefix ...Message) (*Committer, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}

	c := &Committer{
		sessionId: sessionId,
		prefix:    encode(prefix...),
		prng:      prng,
	}
	return c, nil
}

func (c *Committer) Commit(message Message) (*Commitment, *Opening, error) {
	if message == nil {
		return nil, nil, errs.NewIsNil("message")
	}

	witness := make([]byte, base.CollisionResistanceBytes)
	if _, err := io.ReadFull(c.prng, witness); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "reading random bytes")
	}

	commitmentValue, err := hashing.Hmac(witness, hashFunc, encodeSessionId(c.sessionId), c.prefix, message)
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
