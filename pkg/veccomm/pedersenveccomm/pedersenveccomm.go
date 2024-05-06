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

type Vector = veccomm.Vector[pedersencomm.Message]

type Opening struct {
	opening pedersencomm.Opening
	Vector_ veccomm.Vector[pedersencomm.Message]
}

var _ comm.Opening[Vector] = (*Opening)(nil)

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

func (c *VectorCommitter) Commit(vector Vector) (*VectorCommitment, *Opening, error) {
	if c == nil {
		return nil, nil, errs.NewIsNil("receiver")
	}
	curve := c.committer.Generator.Curve()
	nonce, err := curve.ScalarField().Random(c.committer.Prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not draw the nonce at random")
	}
	witness, err := curve.ScalarField().Random(c.committer.Prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not draw the witness at random")
	}
	commitment := c.committer.Generator.ScalarMul(witness)
	for _, msg := range vector {
		localGenerator := curve.Generator().ScalarMul(nonce)
		nonce = nonce.Increment()
		mG := localGenerator.ScalarMul(msg)
		commitment = commitment.Add(mG)
	}
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not compute commitment")
	}
	return &VectorCommitment{&pedersencomm.Commitment{commitment}, uint(len(vector))}, &Opening{pedersencomm.Opening{nil, witness}, vector}, nil
}

func (v *VectorVerifier) Verify(veccom *VectorCommitment, opening *Opening) error {
	if v == nil {
		return errs.NewIsNil("receiver")
	}
	err := v.verifier.Verify(*veccom.commitment, &opening.opening)
	if err != nil {
		return errs.NewVerification("verification failed")
	}
	return nil
}

func (c *VectorCommitter) OpenAtIndex(index uint, vector Vector, fullOpening *Opening) (opening comm.Opening[pedersencomm.Message], err error) {
	panic("implement me")
}

func (v *VectorVerifier) VerifyAtIndex(index uint, vector Vector, opening comm.Opening[pedersencomm.Message]) error {
	panic("implement me")
}
