package schnorr

import (
	"crypto/rand"

	"github.com/pkg/errors"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves/native"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"

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
	C         curves.Scalar
	S         curves.Scalar
	Statement curves.Point
}

// NewProver generates a `Prover` object, ready to generate Schnorr proofs on any given point.
func NewProver(basePoint curves.Point, uniqueSessionId []byte, transcript *merlin.Transcript) (*Prover, error) {
	if basePoint == nil {
		return nil, errors.New("basepoint can't be nil")
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
func (p *Prover) Prove(x curves.Scalar) (*Proof, error) {
	var err error
	result := &Proof{}

	curve := curves.GetCurveByName(p.BasePoint.CurveName())
	if curve == nil {
		return nil, errors.New("curve is nil")
	}

	result.Statement = p.BasePoint.Mul(x)
	k := curve.Scalar.Random(rand.Reader)
	R := p.BasePoint.Mul(k)

	p.transcript.AppendMessage([]byte(basepointLabel), p.BasePoint.ToAffineCompressed())
	p.transcript.AppendMessage([]byte(rLabel), R.ToAffineCompressed())
	p.transcript.AppendMessage([]byte(statementLabel), result.Statement.ToAffineCompressed())
	p.transcript.AppendMessage([]byte(uniqueSessionIdLabel), p.uniqueSessionId)
	digest := p.transcript.ExtractBytes([]byte(digestLabel), native.FieldBytes)

	result.C, err = curve.Scalar.SetBytes(digest)
	if err != nil {
		return nil, errors.Wrap(err, "could not produce fiat shamir challenge scalar")
	}
	result.S = result.C.Mul(x).Add(k)
	return result, nil
}

// Verify verifies the `proof`, given the prover parameters `scalar` and `curve`.
func Verify(basePoint curves.Point, proof *Proof, uniqueSessionId []byte, transcript *merlin.Transcript) error {
	if transcript == nil {
		transcript = merlin.NewTranscript(domainSeparationLabel)
	}
	if basePoint == nil {
		return errors.New("basepoint is nil")
	}
	if basePoint.IsIdentity() {
		return errors.New("basepoint is identity")
	}

	curve := curves.GetCurveByName(basePoint.CurveName())
	if curve == nil {
		return errors.New("curve is nil")
	}

	if proof == nil {
		return errors.New("proof is nil")
	}

	gs := basePoint.Mul(proof.S)
	xc := proof.Statement.Mul(proof.C.Neg())
	R := gs.Add(xc)

	transcript.AppendMessage([]byte(basepointLabel), basePoint.ToAffineCompressed())
	transcript.AppendMessage([]byte(rLabel), R.ToAffineCompressed())
	transcript.AppendMessage([]byte(statementLabel), proof.Statement.ToAffineCompressed())
	transcript.AppendMessage([]byte(uniqueSessionIdLabel), uniqueSessionId)
	digest := transcript.ExtractBytes([]byte(digestLabel), native.FieldBytes)

	computedChallenge, err := curve.Scalar.SetBytes(digest)
	if err != nil {
		return errors.Wrap(err, "could not produce fiat shamir challenge scalar")
	}

	if computedChallenge.Cmp(proof.C) != 0 {
		return errors.New("schnorr verification failed")
	}
	return nil
}

// TODO: Remove during KEY-51
func ComputeFiatShamirChallege(cipherSuite *integration.CipherSuite, xs [][]byte) (curves.Scalar, error) {
	if err := cipherSuite.Validate(); err != nil {
		return nil, errors.Wrap(err, "ciphersuite is invalid")
	}

	H := cipherSuite.Hash()
	for _, x := range xs {
		if _, err := H.Write(x); err != nil {
			return nil, errors.Wrap(err, "could not write to H")
		}
	}

	digest := H.Sum(nil)
	var setBytesFunc func([]byte) (curves.Scalar, error)
	switch len(digest) {
	case native.FieldBytes:
		setBytesFunc = cipherSuite.Curve.Scalar.SetBytes
	case native.WideFieldBytes:
		setBytesFunc = cipherSuite.Curve.Scalar.SetBytesWide
	default:
		return nil, errors.Errorf("digest length %d unsporrted", len(digest))
	}

	challenge, err := setBytesFunc(digest)
	if err != nil {
		return nil, errors.Wrap(err, "could not compute challenge scalar")
	}
	return challenge, nil
}
