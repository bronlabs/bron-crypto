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

type Opening struct {
	opening hashcomm.Opening
	vector  veccomm.Vector[hashcomm.Message]
}

func (o *Opening) Message() veccomm.Vector[hashcomm.Message] {
	return o.vector
}

type VectorCommitment struct {
	commitment hashcomm.Commitment
	length     uint
}

func (vc *VectorCommitment) Length() uint {
	return vc.length
}

var _ veccomm.VectorCommitment = (*VectorCommitment)(nil)

type VectorCommitter struct {
	committer *hashcomm.Committer
}

var _ veccomm.VectorCommitter[hashcomm.Message, *VectorCommitment, *Opening] = (*VectorCommitter)(nil)

type VectorVerifier struct {
	verifier *hashcomm.Verifier
}

var _ veccomm.VectorVerifier[hashcomm.Message, *VectorCommitment, *Opening] = (*VectorVerifier)(nil)

// not UC-secure without session-id
func NewVectorCommitter(sessionId []byte, prng io.Reader) (*VectorCommitter, error) {
	committer, err := hashcomm.NewCommitter(sessionId, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not instantiate a committer")
	}
	return &VectorCommitter{committer}, nil
}

// not UC-secure without session-id
func NewVectorVerifier(sessionId []byte) (*VectorVerifier, error) {
	committer, err := hashcomm.NewVerifier(sessionId)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not instantiate a verifier")
	}
	return &VectorVerifier{committer}, nil
}

func encode(msg []byte, i int) []byte {
	return slices.Concat(bitstring.ToBytes32LE(int32(i)), bitstring.ToBytes32LE(int32(len(msg))), msg)
}

func chainEncodingVector(vector veccomm.Vector[hashcomm.Message]) hashcomm.Message {
	encoded := make([][]byte, len(vector))
	for i, m := range vector {
		encoded[i] = encode(m, i)
		if i > 0 {
			encoded[i] = append(encoded[i-1], encoded[i]...)
		}
	}
	return bytes.Join(encoded, nil)
}

func (c *VectorCommitter) Commit(vector veccomm.Vector[hashcomm.Message]) (*VectorCommitment, *Opening, error) {
	if c == nil {
		return nil, nil, errs.NewIsNil("receiver")
	}
	commitment, opening, err := c.committer.Commit(chainEncodingVector(vector))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not compute commitment")
	}
	return &VectorCommitment{commitment, uint(len(vector))}, &Opening{opening, vector}, nil
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

func (v *VectorVerifier) Verify(veccom *VectorCommitment, opening *Opening) error {
	if v == nil {
		return errs.NewIsNil("receiver")
	}
	if err := veccom.Validate(); err != nil {
		return errs.WrapFailed(err, "commitment not valid")
	}
	if !(bytes.Equal(chainEncodingVector(opening.vector), opening.opening.Message_)) {
		return errs.NewVerification("commitment is not tied to the vector")
	}
	err := v.verifier.Verify(veccom.commitment, &opening.opening)
	if err != nil {
		return errs.NewVerification("verification failed")
	}
	return nil
}

func (c *VectorCommitter) OpenAtIndex(index uint, vector veccomm.Vector[hashcomm.Message], fullOpening *Opening) (opening *comm.Opening[hashcomm.Message], err error) {
	panic("implement me")
}

func (v *VectorVerifier) VerifyAtIndex(index uint, vector veccomm.Vector[hashcomm.Message], fullOpening comm.Opening[hashcomm.Message]) error {
	panic("implement me")
}
