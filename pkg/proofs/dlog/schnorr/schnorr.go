package schnorr

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	domainSeparationLabel = "COPPER_ZKPOK_DLOG_SCHNORR-"
	basepointLabel        = "basepoint"
	rLabel                = "R"
	statementLabel        = "statement"
	uniqueSessionIdLabel  = "unique session id"
	digestLabel           = "digest"
)

type Statement = dlog.Statement

type Prover struct {
	uniqueSessionId []byte
	transcript      transcripts.Transcript
	BasePoint       curves.Point

	_ types.Incomparable
}

// Proof contains the (c, s) schnorr proof. `Statement` is the curve point you're proving knowledge of discrete log of,
// with respect to the base point.
type Proof struct {
	C curves.Scalar
	S curves.Scalar

	_ types.Incomparable
}

// NewProver generates a `Prover` object, ready to generate Schnorr proofs on any given point.
func NewProver(basePoint curves.Point, uniqueSessionId []byte, transcript transcripts.Transcript) (*Prover, error) {
	err := validateInputs(basePoint, uniqueSessionId)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to validate inputs")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(domainSeparationLabel, nil)
	}
	return &Prover{
		BasePoint:       basePoint,
		uniqueSessionId: uniqueSessionId,
		transcript:      transcript,
	}, nil
}

func validateInputs(basePoint curves.Point, uniqueSessionId []byte) error {
	if basePoint == nil {
		return errs.NewInvalidArgument("basepoint can't be nil")
	}
	if basePoint.IsIdentity() {
		return errs.NewIsIdentity("basepoint is identity")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewInvalidArgument("unique session id can't be empty")
	}
	return nil
}

// Prove generates and returns a Schnorr proof, given the scalar witness `x`.
// in the process, it will actually also construct the statement (just one curve mult in this case).
func (p *Prover) Prove(x curves.Scalar, prng io.Reader) (*Proof, Statement, error) {
	var err error
	result := &Proof{}

	curve := p.BasePoint.Curve()

	statement := p.BasePoint.Mul(x)
	k, err := curve.Scalar().Random(prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "could not sample random scalar")
	}
	R := p.BasePoint.Mul(k)

	p.transcript.AppendPoints(basepointLabel, p.BasePoint)
	p.transcript.AppendPoints(rLabel, R)
	p.transcript.AppendPoints(statementLabel, statement)
	p.transcript.AppendMessages(uniqueSessionIdLabel, p.uniqueSessionId)
	digest, err := p.transcript.ExtractBytes(digestLabel, base.WideFieldBytes)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not produce fiat shamir challenge bytes")
	}

	result.C, err = curve.Scalar().SetBytesWide(digest)
	if err != nil {
		return nil, nil, errs.WrapSerializationError(err, "could not produce fiat shamir challenge scalar")
	}
	result.S = result.C.Mul(x).Add(k)
	return result, statement, nil
}

// Verify verifies the `proof`, given the prover parameters `scalar` and `curve` against the `statement`.
func Verify(basePoint curves.Point, statement Statement, proof *Proof, uniqueSessionId []byte, transcript transcripts.Transcript) error {
	if transcript == nil {
		transcript = hagrid.NewTranscript(domainSeparationLabel, nil)
	}
	if basePoint == nil {
		return errs.NewInvalidArgument("basepoint is nil")
	}
	if basePoint.IsIdentity() {
		return errs.NewInvalidArgument("basepoint is identity")
	}
	if err := dlog.StatementSubgroupMembershipCheck(basePoint, statement); err != nil {
		return errs.WrapFailed(err, "subgroup membership check failed")
	}

	curve := basePoint.Curve()

	if proof == nil {
		return errs.NewInvalidArgument("proof is nil")
	}

	gs := basePoint.Mul(proof.S)
	xc := statement.Mul(proof.C.Neg())
	R := gs.Add(xc)

	transcript.AppendPoints(basepointLabel, basePoint)
	transcript.AppendPoints(rLabel, R)
	transcript.AppendPoints(statementLabel, statement)
	transcript.AppendMessages(uniqueSessionIdLabel, uniqueSessionId)
	digest, err := transcript.ExtractBytes(digestLabel, base.WideFieldBytes)
	if err != nil {
		return errs.WrapFailed(err, "could not extract bytes from transcript")
	}

	computedChallenge, err := curve.Scalar().SetBytesWide(digest)
	if err != nil {
		return errs.WrapSerializationError(err, "could not produce fiat shamir challenge scalar")
	}

	if computedChallenge.Cmp(proof.C) != 0 {
		return errs.NewVerificationFailed("schnorr verification failed")
	}
	return nil
}
