package pedersenveccomm

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
	"github.com/copperexchange/krypton-primitives/pkg/comm/pedersencomm"
	"github.com/copperexchange/krypton-primitives/pkg/veccomm"
)

const Name = "PEDERSEN_VECTOR_COMMITMENT"

type Opening struct {
	opening pedersencomm.Opening
	Vector_ veccomm.Vector[pedersencomm.Message]
}

func (o *Opening) Message() veccomm.Vector[pedersencomm.Message] {
	return o.Vector_
}

type VectorCommitment struct {
	commitment *pedersencomm.Commitment
	length     uint
}

func (vc *VectorCommitment) Length() uint {
	return vc.length
}

var _ veccomm.VectorCommitment = (*VectorCommitment)(nil)

type VectorCommitter struct {
	committer *pedersencomm.HomomorphicCommitter
}

var _ veccomm.VectorCommitter[pedersencomm.Message, *VectorCommitment, *Opening] = (*VectorCommitter)(nil)

type VectorVerifier struct {
	verifier *pedersencomm.HomomorphicVerifier
}

var _ veccomm.VectorVerifier[pedersencomm.Message, *VectorCommitment, *Opening] = (*VectorVerifier)(nil)

// not UC-secure without session-id
func NewVectorCommitter(sessionId []byte, prng io.Reader, curve curves.Curve) (*VectorCommitter, error) {
	committer, err := pedersencomm.NewHomomorphicCommitter(sessionId, prng, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not instantiate a committer")
	}
	return &VectorCommitter{committer}, nil
}

// not UC-secure without session-id
func NewVectorVerifier(sessionId []byte) (*VectorVerifier, error) {
	committer, err := pedersencomm.NewHomomorphicVerifier(sessionId)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not instantiate a verifier")
	}
	return &VectorVerifier{committer}, nil
}

// Uncomplete at this stage: only commit to the first message
// As pedersencomm is currently implemented, it is not possible to rely on it for vector commitments
// For Pedersen vector commitments, we should pick a single random and use a different point for each msg
// i.e. commitment = rH + m_0G_0 + m_1G_1 + ... + m_iG_i
func (c *VectorCommitter) Commit(vector veccomm.Vector[pedersencomm.Message]) (*VectorCommitment, *Opening, error) {
	commitment, opening, err := c.committer.Commit(vector[0])
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not compute commitment")
	}
	return &VectorCommitment{&commitment, uint(len(vector))}, &Opening{*opening, vector}, nil
}

func (v *VectorVerifier) Verify(veccom *VectorCommitment, opening *Opening) error {
	err := v.verifier.Verify(*veccom.commitment, &opening.opening)
	if err != nil {
		return errs.NewVerification("verification failed")
	}
	return nil
}

func (c *VectorCommitter) OpenAtIndex(index uint, vector veccomm.Vector[pedersencomm.Message], fullOpening *Opening) (opening *comm.Opening[pedersencomm.Message], err error) {
	panic("implement me")
}

func (v *VectorVerifier) VerifyAtIndex(index uint, vector veccomm.Vector[pedersencomm.Message], fullOpening comm.Opening[pedersencomm.Message]) error {
	panic("implement me")
}
