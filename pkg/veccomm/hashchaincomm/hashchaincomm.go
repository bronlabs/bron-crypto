package hashchaincomm

import (
	"io"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm/hashcomm"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/veccomm"
)

const Name = "HASHCHAIN_COMMITMENT"

type VectorCommitter struct {
	prng      io.Reader
	sessionId []byte
}

type VectorVerifier struct {
	sessionId []byte
}

type VectorCommitment struct {
	hashcomm.Commitment
	length uint
}

// not UC-secure without session-id
func NewVectorCommitter(prng io.Reader, sessionId []byte) (*VectorCommitter, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	return &VectorCommitter{prng, sessionId}, nil
}

// not UC-secure without session-id
func NewVectorVerifier(sessionId []byte) (*VectorVerifier, error) {
	return &VectorVerifier{sessionId}, nil
}

func encode(msg []byte, i int) []byte {
	return slices.Concat(bitstring.ToBytes32LE(int32(i)), bitstring.ToBytes32LE(int32(len(msg))), msg)
}

func encodeWithSessionId(sessionId []byte, vector veccomm.Vector[hashcomm.Message]) [][]byte {
	encoded := make([][]byte, len(vector)+1)
	encoded[0] = slices.Concat([]byte("SESSION_ID_"), bitstring.ToBytes32LE(int32(len(sessionId))), sessionId)
	for i, m := range vector {
		encoded[i+1] = encode(m, i)
	}
	return encoded
}

func (c *VectorCommitter) Commit(vector veccomm.Vector[hashcomm.Message]) (*VectorCommitment, *hashcomm.Opening, error) {
	witness := make([]byte, base.CollisionResistanceBytes)
	if _, err := io.ReadFull(c.prng, witness); err != nil {
		return nil, nil, errs.WrapRandomSample(err, "reading random bytes")
	}
	commitment, err := hashing.HmacChain(witness, hashcomm.CommitmentHashFunction, encodeWithSessionId(c.sessionId, vector)...)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not compute commitment")
	}
	return &VectorCommitment{hashcomm.Commitment{Commitment: commitment}, uint(len(vector))}, &hashcomm.Opening{Message_: nil, Witness: witness}, nil
}
