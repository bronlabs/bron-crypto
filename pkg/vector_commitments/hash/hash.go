package hashvectorcommitments

import (
	"bytes"
	"crypto/subtle"
	"slices"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/commitments"
	vc "github.com/bronlabs/krypton-primitives/pkg/vector_commitments"
)

const Name = "HASH_VECTOR_COMMITMENT"

var (
	_ commitments.Opening[Vector] = (*Opening)(nil)
	_ vc.VectorCommitment         = (*VectorCommitment)(nil)
)

type Witness []byte
type Message []byte

type VectorElement = Message

type Vector []VectorElement

func (v Vector) Equal(w vc.Vector[VectorElement]) bool {
	ww, ok := w.(Vector)
	if !ok || len(v) != len(ww) {
		return false
	}
	for i, vi := range v {
		if subtle.ConstantTimeCompare(vi, ww[i]) == 0 {
			return false
		}
	}
	return true
}

type Opening struct {
	witness Witness
	vector  Vector
}

type VectorCommitment struct {
	value []byte
}

func (o *Opening) GetMessage() Vector {
	return o.vector
}

func (vectorCommitment *VectorCommitment) Validate() error {
	if vectorCommitment == nil {
		return errs.NewIsNil("receiver")
	}
	if len(vectorCommitment.value) != base.CollisionResistanceBytes {
		return errs.NewArgument("commitment length (%d) != %d", len(vectorCommitment.value), base.CollisionResistanceBytes)
	}
	return nil
}

func (o *Opening) Validate() error {
	if o == nil {
		return errs.NewIsNil("receiver")
	}
	if len(o.witness) < base.CollisionResistanceBytes {
		return errs.NewArgument("witness length (%d) < %d", len(o.witness), base.CollisionResistanceBytes)
	}
	return nil
}

func encodeSessionId(sessionId []byte) []byte {
	return slices.Concat([]byte("SESSION_ID_"), bitstring.ToBytes32LE(int32(len(sessionId))), sessionId)
}

// Encode the vector as a concatenation of messages along with their position and length.
func encode(v Vector) Message {
	encoded := make([][]byte, len(v))
	for i, m := range v {
		encoded[i] = slices.Concat(bitstring.ToBytes32LE(int32(i)), bitstring.ToBytes32LE(int32(len(m))), m)
	}
	return bytes.Join(encoded, nil)
}
