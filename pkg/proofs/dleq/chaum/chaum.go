package chaum

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/constants"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dleq/chaumuc"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	domainSeparationLabel = "COPPER_DLEQ_CHAUM_PEDERSEN_FIAT_SHAMIR-"
)

type Prover struct {
	uniqueSessionId []byte
	transcript      transcripts.Transcript
	prng            io.Reader

	_ types.Incomparable
}

// Proof contains the (Challenge, reSponse) chaum-pedersen proof.
type Proof struct {
	C curves.Scalar
	S curves.Scalar

	_ types.Incomparable
}

type Statement chaumuc.Statement

// NewProver generates a `Prover` object, ready to generate dleq proofs.
func NewProver(uniqueSessionId []byte, transcript transcripts.Transcript, prng io.Reader) (*Prover, error) {
	prover := &Prover{
		uniqueSessionId: uniqueSessionId,
		transcript:      transcript,
		prng:            prng,
	}
	if err := prover.Validate(); err != nil {
		return nil, errs.WrapFailed(err, "invalid prover")
	}
	prover.transcript.AppendMessages("dleq sid", prover.uniqueSessionId)
	return prover, nil
}

func (p *Prover) Validate() error {
	if p == nil {
		return errs.NewIsNil("prover is nil")
	}
	if p.prng == nil {
		return errs.NewIsNil("prng")
	}
	if p.transcript == nil {
		p.transcript = hagrid.NewTranscript(domainSeparationLabel, nil)
	}
	if len(p.uniqueSessionId) == 0 {
		return errs.NewInvalidArgument("length of session id is 0")
	}
	return nil
}

// Prove proves in zero-knowledge the equality of the dlog of x*H1 and x*H2.
func (p *Prover) Prove(x curves.Scalar, H1, H2 curves.Point, extraChallengeElements ...[]byte) (*Proof, *Statement, error) {
	if x == nil || H1 == nil || H2 == nil {
		return nil, nil, errs.NewIsNil("main arguments can't be nil")
	}

	curve := x.Curve()

	// step 1 and 2
	statement := &Statement{
		H1: H1,
		H2: H2,
		P1: H1.Mul(x),
		P2: H2.Mul(x),
	}

	// step 3
	k, err := curve.Scalar().Random(p.prng)
	if err != nil {
		return nil, nil, errs.WrapRandomSampleFailed(err, "could not generate random scalar")
	}
	// step 4
	R1 := H1.Mul(k)
	// step 5
	R2 := H2.Mul(k)

	// step 6
	p.transcript.AppendPoints("H1", H1)
	p.transcript.AppendPoints("H2", H2)
	p.transcript.AppendPoints("P1", statement.P1)
	p.transcript.AppendPoints("P2", statement.P2)
	p.transcript.AppendPoints("R1", R1)
	p.transcript.AppendPoints("R2", R2)
	p.transcript.AppendMessages("extra elements", extraChallengeElements...)

	digest, err := p.transcript.ExtractBytes("challenge bytes", constants.FieldBytes)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not produce fiat shamir challenge scalar")
	}

	c, err := curve.Scalar().Hash(digest)
	if err != nil {
		return nil, nil, errs.WrapHashingFailed(err, "could not produce fiat shamir challenge scalar")
	}
	// step 7
	s := c.Mul(x).Add(k)
	// step 8
	return &Proof{
		C: c,
		S: s,
	}, statement, nil
}

// Verify verifies the `proof`, given the prover parameters against the `statement`.
func Verify(statement *Statement, proof *Proof, uniqueSessionId []byte, transcript transcripts.Transcript, extraChallengeElements ...[]byte) error {
	if transcript == nil {
		transcript = hagrid.NewTranscript(domainSeparationLabel, nil)
		transcript.AppendMessages("dleq sid", uniqueSessionId)
	}

	if statement == nil || statement.H1 == nil || statement.H2 == nil || statement.P1 == nil || statement.P2 == nil {
		return errs.NewInvalidArgument("invalid statement")
	}
	if proof == nil || proof.C == nil || proof.C.IsZero() || proof.S == nil || proof.S.IsZero() {
		return errs.NewInvalidArgument("proof is nil")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewInvalidArgument("length of session id is 0")
	}

	if err := dlog.StatementSubgroupMembershipCheck(statement.H1, statement.P1); err != nil {
		return errs.WrapFailed(err, "subgroup membership check failed for P1")
	}
	if err := dlog.StatementSubgroupMembershipCheck(statement.H2, statement.P2); err != nil {
		return errs.WrapFailed(err, "subgroup membership check failed for P2")
	}

	curve := statement.H1.Curve()

	// step 1
	R1 := statement.H1.Mul(proof.S).Sub(statement.P1.Mul(proof.C))
	// step 2
	R2 := statement.H2.Mul(proof.S).Sub(statement.P2.Mul(proof.C))

	// step 3, Fiat-Shamir
	transcript.AppendPoints("H1", statement.H1)
	transcript.AppendPoints("H2", statement.H2)
	transcript.AppendPoints("P1", statement.P1)
	transcript.AppendPoints("P2", statement.P2)
	transcript.AppendPoints("R1", R1)
	transcript.AppendPoints("R2", R2)
	transcript.AppendMessages("extra elements", extraChallengeElements...)

	digest, err := transcript.ExtractBytes("challenge bytes", constants.FieldBytes)
	if err != nil {
		return errs.WrapFailed(err, "could not extract bytes from transcript")
	}
	recomputedChallenge, err := curve.Scalar().Hash(digest)
	if err != nil {
		return errs.WrapHashingFailed(err, "could not produce fiat shamir challenge scalar")
	}

	// step 4
	if isEqual := proof.C.Cmp(recomputedChallenge) == 0; !isEqual {
		return errs.NewVerificationFailed("invalid proof")
	}
	// step 5
	return nil
}
