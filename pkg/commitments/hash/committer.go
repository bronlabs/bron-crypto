package hashcommitments

import (
	"io"
	"slices"

	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
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
		prefix:    slices.Concat(prefix...),
		prng:      prng,
	}
	return c, nil
}

func (c *Committer) Commit(message Message) (*Commitment, *Opening, error) {
	if message == nil {
		return nil, nil, errs.NewIsNil("Message")
	}

	witness := make([]byte, base.CollisionResistanceBytes)
	if _, err := io.ReadFull(c.prng, witness); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "reading random bytes")
	}

	commitmentValue, err := hashing.KmacPrefixedLength(witness, nil, sha3.NewCShake128, encodeSessionId(c.sessionId), c.prefix, message)
	if err != nil {
		return nil, nil, errs.WrapHashing(err, "could not compute commitment")
	}

	commitment := &Commitment{
		Value: commitmentValue,
	}
	opening := &Opening{
		Message: message,
		Witness: witness,
	}
	return commitment, opening, nil
}
