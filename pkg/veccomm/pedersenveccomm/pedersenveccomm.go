package pedersenveccomm

import (
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

type Vector = veccomm.Vector[pedersencomm.Message]

type Opening struct {
	opening pedersencomm.Opening
	nonce   curves.Scalar
	Vector_ veccomm.Vector[pedersencomm.Message]
}

var _ comm.Opening[Vector] = (*Opening)(nil)

func (o *Opening) Message() veccomm.Vector[pedersencomm.Message] {
	return o.Vector_
}

type VectorHomomorphicCommitmentScheme struct{}

var _ comm.HomomorphicCommitmentScheme[Vector, VectorCommitment, *Opening] = (*VectorHomomorphicCommitmentScheme)(nil)

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
	VectorHomomorphicCommitmentScheme
}

var _ veccomm.VectorCommitter[pedersencomm.Message, *VectorCommitment, *Opening] = (*VectorCommitter)(nil)

type VectorVerifier struct {
	verifier *pedersencomm.HomomorphicVerifier
	VectorHomomorphicCommitmentScheme
}

var _ veccomm.VectorVerifier[pedersencomm.Message, *VectorCommitment, *Opening] = (*VectorVerifier)(nil)

// not UC-secure without session-id
func NewVectorCommitter(sessionId []byte, prng io.Reader, curve curves.Curve) (*VectorCommitter, error) {
	committer, err := pedersencomm.NewHomomorphicCommitter(sessionId, prng, curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not instantiate a committer")
	}
	return &VectorCommitter{committer, VectorHomomorphicCommitmentScheme{}}, nil
}

// not UC-secure without session-id
func NewVectorVerifier(sessionId []byte) (*VectorVerifier, error) {
	committer, err := pedersencomm.NewHomomorphicVerifier(sessionId)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not instantiate a verifier")
	}
	return &VectorVerifier{committer, VectorHomomorphicCommitmentScheme{}}, nil
}

func (c *VectorCommitter) Commit(vector Vector) (*VectorCommitment, *Opening, error) {
	if c == nil {
		return nil, nil, errs.NewIsNil("receiver")
	}
	curve := c.committer.Generator.Curve()
	nonce, err := curve.ScalarField().Random(c.committer.Prng)
	initialNonce := nonce
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
	return &VectorCommitment{&pedersencomm.Commitment{commitment}, uint(len(vector))}, &Opening{pedersencomm.Opening{nil, witness}, initialNonce, vector}, nil
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
	return vc.commitment.Validate()
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

func (v *VectorVerifier) Verify(veccom *VectorCommitment, opening *Opening) error {
	if v == nil {
		return errs.NewIsNil("receiver")
	}
	if err := veccom.Validate(); err != nil {
		return errs.WrapFailed(err, "unvalid commitment")
	}
	if err := opening.Validate(); err != nil {
		return errs.WrapFailed(err, "unvalid opening")
	}
	curve := veccom.commitment.Commitment.Curve()
	// Reconstructs the binding term
	hBytes, err := hashing.HashChain(base.RandomOracleHashFunction, v.verifier.SessionId, pedersencomm.SomethingUpMySleeve)
	if err != nil {
		return errs.WrapHashing(err, "could not produce dlog of H")
	}
	h, err := curve.Hash(hBytes)
	if err != nil {
		return errs.WrapHashing(err, "failed to hash to curve for H")
	}
	localCommitment := h.ScalarMul(opening.opening.Witness)
	// Reconstructs the committed values
	localNonce := opening.nonce.Clone()
	for _, msg := range opening.Vector_ {
		localGenerator := curve.Generator().ScalarMul(localNonce)
		localNonce = localNonce.Increment()
		mG := localGenerator.ScalarMul(msg)
		localCommitment = localCommitment.Add(mG)
	}
	if !veccom.commitment.Commitment.Equal(localCommitment) {
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

func (vhcs *VectorHomomorphicCommitmentScheme) CombineCommitments(x VectorCommitment, ys ...VectorCommitment) (VectorCommitment, error) {
	if vhcs == nil {
		return VectorCommitment{}, errs.NewIsNil("receiver")
	}
	if len(ys) == 0 {
		return x, nil
	}
	acc := x
	for _, y := range ys {
		if y.length != x.length {
			return VectorCommitment{}, errs.NewFailed("vector length mismatch")
		}
		acc.commitment.Commitment = acc.commitment.Commitment.Add(y.commitment.Commitment)
	}
	return acc, nil
}
func (vhcs *VectorHomomorphicCommitmentScheme) ScaleCommitment(x VectorCommitment, n *saferith.Nat) (VectorCommitment, error) {
	if vhcs == nil {
		return VectorCommitment{}, errs.NewIsNil("receiver")
	}
	curve := x.commitment.Commitment.Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	return VectorCommitment{&pedersencomm.Commitment{x.commitment.Commitment.ScalarMul(scale)}, x.length}, nil
}

func (vhcs *VectorHomomorphicCommitmentScheme) CombineOpenings(x *Opening, ys ...*Opening) (*Opening, error) {
	if vhcs == nil {
		return nil, errs.NewIsNil("receiver")
	}
	if len(ys) == 0 {
		return x, nil
	}
	acc := &Opening{pedersencomm.Opening{x.opening.Message_.Clone(), x.opening.Witness.Clone()}, x.nonce.Clone(), x.Vector_}
	for i, y := range ys {
		if len(y.Vector_) != len(x.Vector_) {
			return nil, errs.NewFailed("vector length mismatch")
		}
		acc.opening.Witness = acc.opening.Witness.Add(y.opening.Witness)
		acc.Vector_[i] = acc.Vector_[i].Add(y.Vector_[i])
	}
	return acc, nil
}

func (vhcs *VectorHomomorphicCommitmentScheme) ScaleOpening(x *Opening, n *saferith.Nat) (*Opening, error) {
	if vhcs == nil {
		return nil, errs.NewIsNil("receiver")
	}
	curve := x.opening.Witness.ScalarField().Curve()
	scale := curve.ScalarField().Scalar().SetNat(n)
	acc := &Opening{pedersencomm.Opening{x.opening.Message_.Clone(), x.opening.Witness.Clone()}, x.nonce.Clone(), x.Vector_}
	acc.opening.Witness = acc.opening.Witness.Mul(scale)
	for i, _ := range x.Vector_ {
		acc.Vector_[i] = acc.Vector_[i].Mul(scale)
	}
	return acc, nil
}
