package hashveccomm

import (
	"bytes"
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

type Vector = veccomm.Vector[hashcomm.Message]

type Opening struct {
	opening *hashcomm.Opening
	vector  Vector
}

type VectorCommitment struct {
	commitment *hashcomm.Commitment
	length     uint
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
	if err := o.opening.Validate(); err != nil {
		return errs.WrapValidation(err, "invalid opening")
	}
	return nil
}

// Encode the vector as a concatenation of messages along with their position and length.
func encode(vector veccomm.Vector[hashcomm.Message]) hashcomm.Message {
	encoded := make([][]byte, len(vector))
	for i, m := range vector {
		encoded[i] = slices.Concat(bitstring.ToBytes32LE(int32(i)), bitstring.ToBytes32LE(int32(len(m))), m)
	}
	return bytes.Join(encoded, nil)
}
