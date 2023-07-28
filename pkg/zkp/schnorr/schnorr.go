package schnorr

import (
	"crypto/rand"

	"github.com/pkg/errors"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves/native"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"

	"github.com/gtank/merlin"
)

const domainSeparationLabel = "COPPER_ZKPOK_DLOG_SCHNORR"
const basepointLabel = "basepoint"
const rLabel = "R"
const statementLabel = "statement"
const uniqueSessionIdLabel = "unique session id"
const digestLabel = "digest"

type Prover struct {
	BasePoint       curves.Point
	uniqueSessionId []byte
	transcript      *merlin.Transcript
}

// Proof contains the (c, s) schnorr proof. `Statement` is the curve point you're proving knowledge of discrete log of,
// with respect to the base point.
type Proof struct {
	C curves.Scalar
	S curves.Scalar
}

type Statement = curves.Point

// NewProver generates a `Prover` object, ready to generate Schnorr proofs on any given point.
func NewProver(basePoint curves.Point, uniqueSessionId []byte, transcript *merlin.Transcript) (*Prover, error) {
	if basePoint == nil {
		return nil, errs.NewInvalidArgument("basepoint can't be nil")
	}
	if basePoint.IsIdentity() {
		return nil, errors.New("basepoint is identity")
	}
	if transcript == nil {
		transcript = merlin.NewTranscript(domainSeparationLabel)
	}
	return &Prover{
		BasePoint:       basePoint,
		uniqueSessionId: uniqueSessionId,
		transcript:      transcript,
	}, nil
}

// Prove generates and returns a Schnorr proof, given the scalar witness `x`.
// in the process, it will actually also construct the statement (just one curve mult in this case)
func (p *Prover) Prove(x curves.Scalar) (*Proof, Statement, error) {
	var err error
	result := &Proof{}

	curve, err := curves.GetCurveByName(p.BasePoint.CurveName())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not get curve by name")
	}

	statement := p.BasePoint.Mul(x)
	k := curve.Scalar.Random(rand.Reader)
	R := p.BasePoint.Mul(k)

	p.transcript.AppendMessage([]byte(basepointLabel), p.BasePoint.ToAffineCompressed())
	p.transcript.AppendMessage([]byte(rLabel), R.ToAffineCompressed())
	p.transcript.AppendMessage([]byte(statementLabel), statement.ToAffineCompressed())
	p.transcript.AppendMessage([]byte(uniqueSessionIdLabel), p.uniqueSessionId)
	digest := p.transcript.ExtractBytes([]byte(digestLabel), native.FieldBytes)

	result.C, err = curve.Scalar.SetBytes(digest)
	if err != nil {
		return nil, nil, errs.WrapDeserializationFailed(err, "could not produce fiat shamir challenge scalar")
	}
	result.S = result.C.Mul(x).Add(k)
	return result, statement, nil
}

// Verify verifies the `proof`, given the prover parameters `scalar` and `curve` against the `statement`.
func Verify(basePoint curves.Point, statement Statement, proof *Proof, uniqueSessionId []byte, transcript *merlin.Transcript) error {
	if transcript == nil {
		transcript = merlin.NewTranscript(domainSeparationLabel)
	}
	if basePoint == nil {
		return errs.NewInvalidArgument("basepoint is nil")
	}
	if basePoint.IsIdentity() {
		return errs.NewInvalidArgument("basepoint is identity")
	}

	curve, err := curves.GetCurveByName(basePoint.CurveName())
	if err != nil {
		return errs.WrapFailed(err, "could not get the curve by name")
	}

	if proof == nil {
		return errs.NewInvalidArgument("proof is nil")
	}

	gs := basePoint.Mul(proof.S)
	xc := statement.Mul(proof.C.Neg())
	R := gs.Add(xc)

	transcript.AppendMessage([]byte(basepointLabel), basePoint.ToAffineCompressed())
	transcript.AppendMessage([]byte(rLabel), R.ToAffineCompressed())
	transcript.AppendMessage([]byte(statementLabel), statement.ToAffineCompressed())
	transcript.AppendMessage([]byte(uniqueSessionIdLabel), uniqueSessionId)
	digest := transcript.ExtractBytes([]byte(digestLabel), native.FieldBytes)

	computedChallenge, err := curve.Scalar.SetBytes(digest)
	if err != nil {
		return errs.WrapDeserializationFailed(err, "could not produce fiat shamir challenge scalar")
	}

	if computedChallenge.Cmp(proof.C) != 0 {
		return errs.NewVerificationFailed("schnorr verification failed")
	}
	return nil
}
