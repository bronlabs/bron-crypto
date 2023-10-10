package fischlin

import (
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	domainSeparationLabel = "COPPER_ZKPOK_DLOG_FISCHLIN-"
	Lambda                = 128 // computational security parameter
	k                     = 7   // ceil(log2(Lambda))
	L                     = 8
	R                     = Lambda / L
	T                     = k * L

	LambdaBytes = Lambda / 8
	LBytes      = L / 8
	RBytes      = R / 8
	TBytes      = T / 8
)

type Statement = dlog.Statement

type Prover struct {
	uniqueSessionId []byte
	transcript      transcripts.Transcript
	prng            io.Reader
	BasePoint       curves.Point

	_ types.Incomparable
}

type Proof struct {
	A [RBytes]curves.Point
	E [RBytes]curves.Scalar
	Z [RBytes]curves.Scalar

	_ types.Incomparable
}

// NewProver generates a `Prover` object, ready to generate dlog proofs on any given point.
func NewProver(basePoint curves.Point, uniqueSessionId []byte, transcript transcripts.Transcript, prng io.Reader) (*Prover, error) {
	prover := &Prover{
		BasePoint:       basePoint,
		uniqueSessionId: uniqueSessionId,
		transcript:      transcript,
		prng:            prng,
	}
	if err := prover.validate(); err != nil {
		return nil, errs.WrapFailed(err, "invalid prover")
	}
	prover.transcript.AppendMessages("Randomised Fischlin proof", prover.uniqueSessionId)
	return prover, nil
}

// Prove proves knowledge of dlog of the statement, using Fischlin.
func (p *Prover) Prove(x curves.Scalar, extraChellengeElements ...[]byte) (*Proof, Statement, error) {
	curve := p.BasePoint.Curve()
	statement := p.BasePoint.Mul(x)
	p.transcript.AppendPoints("statement", statement)

	a := [RBytes]curves.Scalar{}
	A := [RBytes]curves.Point{}
	for i := 0; i < RBytes; i++ {
		// step P.1
		a[i] = curve.Scalar().Random(p.prng)
		// step P.2
		A[i] = p.BasePoint.Mul(a[i])
	}
	e := [RBytes]curves.Scalar{}
	z := [RBytes]curves.Scalar{}

	// step P.3
	for i := 0; i < RBytes; i++ {
		// step P.3.1
		E_i := [][TBytes]byte{}
		solvedHash := false
		for !solvedHash {
			// step P.3.2
			e_i_bytes, err := sample(E_i, p.prng)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "cannot sample challenge")
			}
			// we are hashing e_i to the scalar field for ease of use. We still have the right amount of entropy
			e_i := curve.Scalar().Hash(e_i_bytes[:])

			// step P.3.3
			z_i := a[i].Add(x.Mul(e_i))
			// step P.3.4
			hashResult, err := h(p.BasePoint, A, i, e_i, z_i, p.uniqueSessionId, extraChellengeElements...)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "could not do the PoW hash")
			}
			// step P.3.5
			if allZero(hashResult[:]) {
				solvedHash = true
				e[i] = e_i
				z[i] = z_i
			} else {
				E_i = append(E_i, e_i_bytes)
			}
		}
	}
	// step P.4
	return &Proof{
		A: A,
		E: e,
		Z: z,
	}, statement, nil
}

func (p *Prover) validate() error {
	if p == nil {
		return errs.NewIsNil("prover is nil")
	}
	if p.BasePoint == nil {
		return errs.NewInvalidArgument("basepoint can't be nil")
	}
	if p.BasePoint.IsIdentity() {
		return errs.NewIsIdentity("basepoint is identity")
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

// Verify verifiers the UC-Secure PoK of dlog of `statement` through Fischlin transform.
func Verify(basePoint curves.Point, statement Statement, proof *Proof, uniqueSessionId []byte, extraChallengeElements ...[]byte) error {
	if basePoint == nil {
		return errs.NewInvalidArgument("basepoint is nil")
	}
	if basePoint.IsIdentity() {
		return errs.NewInvalidArgument("basepoint is identity")
	}
	if proof == nil {
		return errs.NewInvalidArgument("proof is nil")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewInvalidArgument("length of session id is 0")
	}

	if err := dlog.StatementSubgroupMembershipCheck(basePoint, statement); err != nil {
		return errs.WrapFailed(err, "subgroup membership check failed")
	}

	for i := 0; i < RBytes; i++ {
		e_i := proof.E[i]
		z_i := proof.Z[i]
		// step V.2.1
		hashResult, err := h(basePoint, proof.A, i, e_i, z_i, uniqueSessionId, extraChallengeElements...)
		if err != nil {
			return errs.WrapFailed(err, "could not produce the hash result")
		}
		if !allZero(hashResult[:]) {
			return errs.NewVerificationFailed("%d iteration not all zero", i)
		}

		// step V.2.2
		Z_i := basePoint.Mul(z_i)
		APrime := Z_i.Add(statement.Mul(e_i.Neg()))
		if !APrime.Equal(proof.A[i]) {
			return errs.NewVerificationFailed("invalid response for iteration %d", i)
		}
	}
	// step V.3
	return nil
}

// h is the hash used in the PoW.
func h(basepoint curves.Point, A [RBytes]curves.Point, i int, e, z curves.Scalar, sid []byte, extraChellengeElements ...[]byte) ([LBytes]byte, error) {
	message := make([][]byte, RBytes+5+len(extraChellengeElements))
	message[0] = basepoint.ToAffineCompressed()
	for j := 0; j < RBytes; j++ {
		message[j+1] = A[j].ToAffineCompressed()
	}
	message[RBytes+1] = []byte{byte(i)}
	message[RBytes+2] = e.Bytes()
	message[RBytes+3] = z.Bytes()
	message[RBytes+4] = sid
	for j := 0; j < len(extraChellengeElements); j++ {
		message[RBytes+5+j] = extraChellengeElements[j]
	}

	hashed, err := hashing.Hash(sha3.New256, message...)
	if err != nil {
		return [LBytes]byte{}, errs.WrapFailed(err, "could not produce a hash")
	}
	output := [LBytes]byte{}
	copy(output[:], hashed[:LBytes])
	return output, nil
}

func allZero(xs []byte) bool {
	for _, x := range xs {
		if x != byte(0) {
			return false
		}
	}
	return true
}

func sample(E_i [][TBytes]byte, prng io.Reader) ([TBytes]byte, error) {
	e_i := [TBytes]byte{}
	found := false
SAMPLE:
	for !found {
		if _, err := prng.Read(e_i[:]); err != nil {
			return [TBytes]byte{}, errs.WrapRandomSampleFailed(err, "could not read random bytes")
		}
		for _, excluded := range E_i {
			if excluded == e_i {
				continue SAMPLE
			}
		}
		found = true
	}
	return e_i, nil
}
