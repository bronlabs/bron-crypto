package hashveccomm

import (
	"bytes"
	"io"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
	"github.com/copperexchange/krypton-primitives/pkg/comm/hashcomm"
	"github.com/copperexchange/krypton-primitives/pkg/veccomm"
)

const Name = "HASH_VECTOR_COMMITMENT"

var _ comm.Opening[Vector] = (*Opening)(nil)
var _ veccomm.VectorCommitment = (*VectorCommitment)(nil)
var _ veccomm.VectorCommitter[hashcomm.Message, *VectorCommitment, *Opening] = (*VectorCommitter)(nil)
var _ veccomm.VectorVerifier[hashcomm.Message, *VectorCommitment, *Opening] = (*VectorVerifier)(nil)

type Vector = veccomm.Vector[hashcomm.Message]

type Opening struct {
	opening *hashcomm.Opening
	vector  Vector
}

type VectorCommitment struct {
	commitment *hashcomm.Commitment
	length     uint
}

type VectorCommitter struct {
	committer *hashcomm.Committer
}

type VectorVerifier struct {
	verifier *hashcomm.Verifier
}

// not UC-secure without session-id.
func NewVectorCommitter(sessionId []byte, prng io.Reader) (*VectorCommitter, error) {
	committer, err := hashcomm.NewCommitter(sessionId, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not instantiate a committer")
	}
	return &VectorCommitter{committer}, nil
}

// not UC-secure without session-id.
func NewVectorVerifier(sessionId []byte) (*VectorVerifier, error) {
	committer, err := hashcomm.NewVerifier(sessionId)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not instantiate a verifier")
	}
	return &VectorVerifier{committer}, nil
}

func (o *Opening) Message() Vector {
	return o.vector
}

func (vc *VectorCommitment) Length() uint {
	return vc.length
}

func (vc *VectorCommitment) Validate() error {
	if vc == nil {
		return errs.NewIsNil("receiver")
	}
	if vc.length == 0 {
		return errs.NewValidation("vector has no element")
	}
	if err := vc.commitment.Validate(); err != nil {
		return errs.WrapFailed(err, "commitment not valid")
	}
	return nil
}

func (o *Opening) Validate() error {
	if o == nil {
		return errs.NewIsNil("receiver")
	}
	return o.opening.Validate()
}

// Encode the vector as a concatenation of messages along with their position and length.
func encode(vector veccomm.Vector[hashcomm.Message]) hashcomm.Message {
	encoded := make([][]byte, len(vector))
	for i, m := range vector {
		encoded[i] = slices.Concat(bitstring.ToBytes32LE(int32(i)), bitstring.ToBytes32LE(int32(len(m))), m)
	}
	return bytes.Join(encoded, nil)
}

func (c *VectorCommitter) Commit(vector Vector) (*VectorCommitment, *Opening, error) {
	if c == nil {
		return nil, nil, errs.NewIsNil("receiver")
	}
	commitment, opening, err := c.committer.Commit(encode(vector))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not compute commitment")
	}
	return &VectorCommitment{commitment, uint(len(vector))}, &Opening{opening, vector}, nil
}

func (v *VectorVerifier) Verify(vectorCommitment *VectorCommitment, opening *Opening) error {
	if v == nil {
		return errs.NewIsNil("receiver")
	}
	if err := vectorCommitment.Validate(); err != nil {
		return errs.WrapFailed(err, "commitment unvalid")
	}
	if err := opening.Validate(); err != nil {
		return errs.WrapFailed(err, "opening unvalid")
	}
	if int(vectorCommitment.length) != len(opening.vector) {
		return errs.NewVerification("length does not match")
	}
	if !(bytes.Equal(encode(opening.vector), opening.opening.Message())) {
		return errs.NewVerification("commitment is not tied to the vector")
	}
	err := v.verifier.Verify(vectorCommitment.commitment, opening.opening)
	if err != nil {
		return errs.NewVerification("verification failed")
	}
	return nil
}

func (c *VectorCommitter) OpenAtIndex(index uint, vector veccomm.Vector[hashcomm.Message], fullOpening *Opening) (opening comm.Opening[hashcomm.Message], err error) {
	panic("implement me")
}

func (v *VectorVerifier) VerifyAtIndex(index uint, vector veccomm.Vector[hashcomm.Message], opening comm.Opening[hashcomm.Message]) error {
	panic("implement me")
}
