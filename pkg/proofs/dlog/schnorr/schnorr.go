package schnorr

import (
	"crypto/rand"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/proofs/dlog"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

const (
	domainSeparationLabel = "COPPER_ZKPOK_DLOG_SCHNORR"
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

	_ helper_types.Incomparable
}

func (*Prover) IsUC() bool {
	return false
}

// Proof contains the (c, s) schnorr proof. `Statement` is the curve point you're proving knowledge of discrete log of,
// with respect to the base point.
type Proof struct {
	C curves.Scalar
	S curves.Scalar

	_ helper_types.Incomparable
}

// NewProver generates a `Prover` object, ready to generate Schnorr proofs on any given point.
func NewProver(basePoint curves.Point, uniqueSessionId []byte, transcript transcripts.Transcript) (*Prover, error) {
	if basePoint == nil {
		return nil, errs.NewInvalidArgument("basepoint can't be nil")
	}
	if basePoint.IsIdentity() {
		return nil, errs.NewIsIdentity("basepoint is identity")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(domainSeparationLabel)
	}
	return &Prover{
		BasePoint:       basePoint,
		uniqueSessionId: uniqueSessionId,
		transcript:      transcript,
	}, nil
}

// Prove generates and returns a Schnorr proof, given the scalar witness `x`.
// in the process, it will actually also construct the statement (just one curve mult in this case).
func (p *Prover) Prove(x curves.Scalar) (*Proof, Statement, error) {
	var err error
	result := &Proof{}

	curve, err := p.BasePoint.Curve()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not get curve by name")
	}

	statement := p.BasePoint.Mul(x)
	k := curve.Scalar().Random(rand.Reader)
	R := p.BasePoint.Mul(k)

	p.transcript.AppendPoints(basepointLabel, p.BasePoint)
	p.transcript.AppendPoints(rLabel, R)
	p.transcript.AppendPoints(statementLabel, statement)
	p.transcript.AppendMessages(uniqueSessionIdLabel, p.uniqueSessionId)
	digest := p.transcript.ExtractBytes(digestLabel, impl.FieldBytes)

	result.C, err = curve.Scalar().SetBytes(digest)
	if err != nil {
		return nil, nil, errs.WrapDeserializationFailed(err, "could not produce fiat shamir challenge scalar")
	}
	result.S = result.C.Mul(x).Add(k)
	return result, statement, nil
}

// Verify verifies the `proof`, given the prover parameters `scalar` and `curve` against the `statement`.
func Verify(basePoint curves.Point, statement Statement, proof *Proof, uniqueSessionId []byte, transcript transcripts.Transcript) error {
	if transcript == nil {
		transcript = hagrid.NewTranscript(domainSeparationLabel)
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

	curve, err := basePoint.Curve()
	if err != nil {
		return errs.WrapFailed(err, "could not get the curve by name")
	}

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
	digest := transcript.ExtractBytes(digestLabel, impl.FieldBytes)

	computedChallenge, err := curve.Scalar().SetBytes(digest)
	if err != nil {
		return errs.WrapDeserializationFailed(err, "could not produce fiat shamir challenge scalar")
	}

	if computedChallenge.Cmp(proof.C) != 0 {
		return errs.NewVerificationFailed("schnorr verification failed")
	}
	return nil
}
