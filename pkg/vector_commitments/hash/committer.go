package hashvectorcommitments

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	vc "github.com/copperexchange/krypton-primitives/pkg/vector_commitments"
)

var (
	_ vc.VectorCommitter[Message, *VectorCommitment, Vector, *Opening] = (*VectorCommitter)(nil)
)

type VectorCommitter struct {
	sessionId []byte
	prng      io.Reader
}

// not UC-secure without session-id.
func NewVectorCommitter(sessionId []byte, prng io.Reader) (*VectorCommitter, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}

	return &VectorCommitter{
		sessionId: sessionId,
		prng:      prng,
	}, nil
}

func (c *VectorCommitter) Commit(vector Vector) (*VectorCommitment, *Opening, error) {
	if vector == nil {
		return nil, nil, errs.NewIsNil("vector is nil")
	}
	witness := make([]byte, base.CollisionResistanceBytes)
	if _, err := io.ReadFull(c.prng, witness); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "reading random bytes")
	}

	commitmentValue, err := hashing.Hmac(witness, hashFunc, encodeSessionId(c.sessionId), encode(vector))
	if err != nil {
		return nil, nil, errs.WrapHashing(err, "could not compute commitment")
	}

	return &VectorCommitment{
			value: commitmentValue,
		},
		&Opening{
			witness: witness,
			vector:  vector,
		}, nil
}

func (*VectorCommitter) OpenAtIndex(index uint, vector Vector, fullOpening *Opening) (opening commitments.Opening[Message], err error) {
	panic("implement me")
}
