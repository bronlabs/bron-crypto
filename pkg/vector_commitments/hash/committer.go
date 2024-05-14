package hashvectorcommitments

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
	hashcommitments "github.com/copperexchange/krypton-primitives/pkg/commitments/hash"
	vectorcommitments "github.com/copperexchange/krypton-primitives/pkg/vector_commitments"
)

var _ vectorcommitments.VectorCommitter[hashcommitments.Message, *VectorCommitment, *Opening] = (*VectorCommitter)(nil)

type VectorCommitter struct {
	committer *hashcommitments.Committer
}

// not UC-secure without session-id.
func NewVectorCommitter(sessionId []byte, prng io.Reader) (*VectorCommitter, error) {
	committer, err := hashcommitments.NewCommitter(sessionId, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not instantiate a committer")
	}
	return &VectorCommitter{
		committer: committer,
	}, nil
}

func (c *VectorCommitter) Commit(vector Vector) (*VectorCommitment, *Opening, error) {
	if vector == nil {
		return nil, nil, errs.NewIsNil("vector is nil")
	}
	commitment, opening, err := c.committer.Commit(encode(vector))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not compute commitment")
	}
	return &VectorCommitment{
			commitment: commitment,
			length:     uint(len(vector)),
		},
		&Opening{
			opening: opening,
			vector:  vector,
		}, nil
}

func (*VectorCommitter) OpenAtIndex(index uint, vector vectorcommitments.Vector[hashcommitments.Message], fullOpening *Opening) (opening commitments.Opening[hashcommitments.Message], err error) {
	panic("implement me")
}
