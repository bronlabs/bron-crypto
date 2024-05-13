package hashveccomm

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
	"github.com/copperexchange/krypton-primitives/pkg/comm/hashcomm"
	"github.com/copperexchange/krypton-primitives/pkg/veccomm"
)

var _ veccomm.VectorCommitter[hashcomm.Message, *VectorCommitment, *Opening] = (*VectorCommitter)(nil)

type VectorCommitter struct {
	committer *hashcomm.Committer
}

func NewVectorCommitter(sessionId []byte, prng io.Reader) (*VectorCommitter, error) {
	committer, err := hashcomm.NewCommitter(sessionId, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not instantiate a committer")
	}

	c := &VectorCommitter{
		committer: committer,
	}
	return c, nil
}

func (c *VectorCommitter) Commit(vector Vector) (*VectorCommitment, *Opening, error) {
	if vector == nil {
		return nil, nil, errs.NewIsNil("vector is nil")
	}

	commitment, opening, err := c.committer.Commit(encode(vector))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not compute commitment")
	}

	com := &VectorCommitment{
		commitment: commitment,
	}
	opn := &Opening{
		opening: opening,
		vector:  vector,
	}
	return com, opn, nil
}

func (*VectorCommitter) OpenAtIndex(index uint, vector veccomm.Vector[hashcomm.Message], fullOpening *Opening) (opening comm.Opening[hashcomm.Message], err error) {
	panic("implement me")
}
