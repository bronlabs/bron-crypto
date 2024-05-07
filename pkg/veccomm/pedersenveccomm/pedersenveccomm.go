package pedersenveccomm

import (
	"fmt"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm"
	"github.com/copperexchange/krypton-primitives/pkg/comm/pedersencomm"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/veccomm"
	"github.com/cronokirby/saferith"
)

const Name = "PEDERSEN_VECTOR_COMMITMENT"

var _ comm.Opening[Vector] = (*Opening)(nil)
var _ veccomm.VectorCommitment = (*VectorCommitment)(nil)
var _ comm.HomomorphicCommitmentScheme[Vector, *VectorCommitment, *Opening] = (*VectorHomomorphicCommitmentScheme)(nil)
var _ veccomm.VectorCommitter[pedersencomm.Message, *VectorCommitment, *Opening] = (*VectorCommitter)(nil)
var _ veccomm.VectorVerifier[pedersencomm.Message, *VectorCommitment, *Opening] = (*VectorVerifier)(nil)

var (
	// hardcoded seed used to derive generators along with the session-id
	SomethingUpMySleeve = []byte(fmt.Sprintf("COPPER_KRYPTON_%s_SOMETHING_UP_MY_SLEEVE-", Name))
)

type Vector = veccomm.Vector[pedersencomm.Message]

type Opening struct {
	opening *pedersencomm.Opening
	vector  Vector
}

type VectorCommitment struct {
	commitment *pedersencomm.Commitment
	length     uint
}

type VectorHomomorphicCommitmentScheme struct{}

type VectorCommitter struct {
	sessionId []byte
	committer *pedersencomm.HomomorphicCommitter
	VectorHomomorphicCommitmentScheme
}

type VectorVerifier struct {
	sessionId []byte
	verifier  *pedersencomm.HomomorphicVerifier
	VectorHomomorphicCommitmentScheme
}

func (o *VectorHomomorphicCommitmentScheme) SampleGenerators(sessionId []byte, curve curves.Curve, n uint) ([]curves.Point, error) {
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}
	generators := make([]curves.Point, n)
	// Derive points from session identifier and SomethingUpMySleeve
	hBytes, err := hashing.HashChain(base.RandomOracleHashFunction, sessionId, SomethingUpMySleeve)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash sessionId")
	}
	h, err := curve.Hash(hBytes)
	if err != nil {
		return nil, errs.WrapHashing(err, "failed to hash to curve for H")
	}
	// Get generators by computing h+nonce*G
	nonce := curve.ScalarField().MultiplicativeIdentity()
	for i, _ := range generators {
		generators[i] = h.Add(curve.Generator().ScalarMul(nonce))
		nonce = nonce.Increment()
	}
	return generators, nil
}

// not UC-secure without session-id
func NewVectorCommitter(sessionId []byte, prng io.Reader, curve curves.Curve) (*VectorCommitter, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}
	committer, err := pedersencomm.NewHomomorphicCommitter(sessionId, prng, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not instantiate a committer")
	}
	return &VectorCommitter{sessionId, committer, VectorHomomorphicCommitmentScheme{}}, nil
}

// not UC-secure without session-id
func NewVectorVerifier(sessionId []byte, curve curves.Curve) (*VectorVerifier, error) {
	if curve == nil {
		return nil, errs.NewIsNil("curve is nil")
	}
	verifier, err := pedersencomm.NewHomomorphicVerifier(sessionId, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not instantiate a committer")
	}
	return &VectorVerifier{sessionId, verifier, VectorHomomorphicCommitmentScheme{}}, nil
}

func (o *Opening) Message() veccomm.Vector[pedersencomm.Message] {
	return o.vector
}

func (vc *VectorCommitment) Length() uint {
	return vc.length
}

func (c *VectorCommitter) Commit(vector Vector) (*VectorCommitment, *Opening, error) {
	if c == nil {
		return nil, nil, errs.NewIsNil("receiver")
	}
	curve := c.committer.H.Curve()
	witness, err := curve.ScalarField().Random(c.committer.Prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not draw the witness at random")
	}
	h, err := c.SampleGenerators(c.sessionId, curve, uint(len(vector)))
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not generate generators")
	}
	commitment := c.committer.H.ScalarMul(witness)
	for i, msg := range vector {
		commitment = commitment.Add(h[i].ScalarMul(msg))
	}

	// separate declaration because pedersencomm.commitment.message is unexported
	pedersenCommitment := pedersencomm.Opening{}
	pedersenCommitment.Witness = witness

	return &VectorCommitment{commitment: &pedersencomm.Commitment{Value: commitment}, length: uint(len(vector))},
		&Opening{&pedersenCommitment, vector},
		nil
}

func (vc *VectorCommitment) Validate() error {
	if vc == nil {
		return errs.NewIsNil("receiver")
	}
	if vc.commitment == nil {
		return errs.NewIsNil("commitment")
	}
	if vc.length == 0 {
		return errs.NewValidation("zero-length")
	}
	if err := vc.commitment.Validate(); err != nil {
		return errs.WrapValidation(err, "unvalid pedersen commitment")
	}
	return nil
}

func (o *Opening) Validate() error {
	if o == nil {
		return errs.NewIsNil("receiver")
	}
	if o.opening.Witness == nil {
		return errs.NewIsNil("witness")
	}
	return nil
}

func (v *VectorVerifier) Verify(vectorCommitment *VectorCommitment, opening *Opening) error {
	if v == nil {
		return errs.NewIsNil("receiver")
	}
	if err := vectorCommitment.Validate(); err != nil {
		return errs.WrapFailed(err, "unvalid commitment")
	}
	if err := opening.Validate(); err != nil {
		return errs.WrapFailed(err, "unvalid opening")
	}
	curve := vectorCommitment.commitment.Value.Curve()
	h, err := v.SampleGenerators(v.sessionId, curve, vectorCommitment.length)
	if err != nil {
		return errs.WrapFailed(err, "could not generate generators")
	}
	localCommitment := v.verifier.H.ScalarMul(opening.opening.Witness)
	for i, msg := range opening.vector {
		localCommitment = localCommitment.Add(h[i].ScalarMul(msg))
	}
	if !vectorCommitment.commitment.Value.Equal(localCommitment) {
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

func (vhcs *VectorHomomorphicCommitmentScheme) CombineCommitments(x *VectorCommitment, ys ...*VectorCommitment) (*VectorCommitment, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.WrapValidation(err, "unvalid commitment (1st operand)")
	}
	acc := &VectorCommitment{commitment: &pedersencomm.Commitment{Value: x.commitment.Value.Clone()}, length: x.length}
	for _, y := range ys {
		if y.length != x.length {
			return nil, errs.NewFailed("vector length mismatch")
		}
		if err := y.Validate(); err != nil {
			return nil, errs.WrapValidation(err, "unvalid commitment (2nd operand)")
		}
		acc.commitment.Value = acc.commitment.Value.Add(y.commitment.Value)
	}
	return acc, nil
}
func (vhcs *VectorHomomorphicCommitmentScheme) ScaleCommitment(x *VectorCommitment, n *saferith.Nat) (*VectorCommitment, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.WrapValidation(err, "unvalid commitment")
	}
	curve := x.commitment.Value.Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	return &VectorCommitment{commitment: &pedersencomm.Commitment{Value: x.commitment.Value.ScalarMul(scale)},
			length: x.length},
		nil
}

func (vhcs *VectorHomomorphicCommitmentScheme) CombineOpenings(x *Opening, ys ...*Opening) (*Opening, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.WrapValidation(err, "unvalid opening (1st operand)")
	}
	// separate declaration because pedersencomm.commitment.message is unexported
	pedersenCommitment := pedersencomm.Opening{}
	pedersenCommitment.Witness = x.opening.Witness.Clone()
	acc := &Opening{&pedersenCommitment, make(Vector, len(x.vector))}
	copy(acc.vector, x.vector)
	for _, y := range ys {
		if len(y.vector) != len(x.vector) {
			return nil, errs.NewFailed("vector length mismatch")
		}
		if err := y.Validate(); err != nil {
			return nil, errs.WrapValidation(err, "unvalid opening (2nd operand)")
		}
		acc.opening.Witness = acc.opening.Witness.Add(y.opening.Witness)
		for j, yElement := range y.vector {
			acc.vector[j] = acc.vector[j].Add(yElement)
		}
	}
	return acc, nil
}

func (vhcs *VectorHomomorphicCommitmentScheme) ScaleOpening(x *Opening, n *saferith.Nat) (*Opening, error) {
	if err := x.Validate(); err != nil {
		return nil, errs.WrapValidation(err, "unvalid opening")
	}
	curve := x.opening.Witness.ScalarField().Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	// separate declaration because pedersencomm.commitment.message is unexported
	pedersenCommitment := pedersencomm.Opening{}
	pedersenCommitment.Witness = x.opening.Witness.Clone()
	acc := &Opening{&pedersenCommitment, make(Vector, len(x.vector))}
	copy(acc.vector, x.vector)
	acc.opening.Witness = acc.opening.Witness.Mul(scale)
	for i, _ := range x.vector {
		acc.vector[i] = acc.vector[i].Mul(scale)
	}
	return acc, nil
}
