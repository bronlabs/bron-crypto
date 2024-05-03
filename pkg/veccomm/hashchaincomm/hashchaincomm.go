package hashchaincomm

import (
	"bytes"
	"io"
	"slices"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm/hashcomm"
	"github.com/copperexchange/krypton-primitives/pkg/veccomm"
)

const Name = "HASHCHAIN_COMMITMENT"

type VectorCommitter struct {
	committer *hashcomm.Committer
}

type VectorVerifier struct {
	verifier *hashcomm.Verifier
}

type VectorCommitment struct {
	commitment hashcomm.Commitment
	length     uint
}

type Opening struct {
	opening hashcomm.Opening
	Vector_ veccomm.Vector[hashcomm.Message]
}

// not UC-secure without session-id
func NewVectorCommitter(prng io.Reader, sessionId []byte) (*VectorCommitter, error) {
	committer, err := hashcomm.NewCommitter(prng, sessionId)
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
	commitment, opening, err := c.committer.Commit(chainEncodingVector(vector))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not compute commitment")
	}
	return &VectorCommitment{*commitment, uint(len(vector))}, &Opening{*opening, vector}, nil
}

func (v *VectorVerifier) Verify(veccom *VectorCommitment, opening *Opening) error {
	err := v.verifier.Verify(&veccom.commitment, &opening.opening)
	if err != nil {
		return errs.NewVerification("verification failed")
	}
	return nil
}
