package chaumuc

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
	domainSeparationLabel = "COPPER_DLEQ_CHAUM_PEDERSEN_FISCHLIN-"
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

type Prover struct {
	uniqueSessionId []byte
	transcript      transcripts.Transcript
	prng            io.Reader

	_ types.Incomparable
}

type Proof struct {
	A1 [RBytes]curves.Point
	A2 [RBytes]curves.Point
	E  [RBytes]curves.Scalar
	Z  [RBytes]curves.Scalar

	_ types.Incomparable
}

type Statement struct {
	H1 curves.Point
	H2 curves.Point
	P1 curves.Point
	P2 curves.Point
}

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
	prover.transcript.AppendMessages("Chaum-Pedersen proof made non-interactive via Randomised Fischlin proof", prover.uniqueSessionId)
	return prover, nil
}

// Prove proves in zero-knowledge the equality of the dlog of x*H1 and x*H2.
func (p *Prover) Prove(x curves.Scalar, H1, H2 curves.Point, extraChellengeElements ...[]byte) (*Proof, *Statement, error) {
	if x == nil || H1 == nil || H2 == nil {
		return nil, nil, errs.NewIsNil("main arguments can't be nil")
	}

	curve := x.Curve()

	P1 := H1.Mul(x)
	P2 := H2.Mul(x)

	a := [RBytes]curves.Scalar{}
	A1 := [RBytes]curves.Point{}
	A2 := [RBytes]curves.Point{}
	for i := 0; i < RBytes; i++ {
		// step P.1
		a[i] = curve.Scalar().Random(p.prng)
		// step P.2
		A1[i] = H1.Mul(a[i])
		A2[i] = H2.Mul(a[i])
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
			hashResult, err := h(A1, A2, H1, H2, P1, P2, i, e_i, z_i, p.uniqueSessionId, extraChellengeElements...)
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
			A1: A1,
			A2: A2,
			E:  e,
			Z:  z,
		}, &Statement{
			H1: H1,
			H2: H2,
			P1: P1,
			P2: P2,
		}, nil
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

// Verify verifiers the UC-Secure PoK of dlog of `statement` through Fischlin transform.
func Verify(statement *Statement, proof *Proof, uniqueSessionId []byte, extraChallengeElements ...[]byte) error {
	if statement == nil || statement.H1 == nil || statement.H2 == nil || statement.P1 == nil || statement.P2 == nil {
		return errs.NewInvalidArgument("invalid statement")
	}
	if proof == nil || len(proof.E) == 0 || len(proof.Z) == 0 || len(proof.A1) == 0 || len(proof.A2) == 0 {
		return errs.NewInvalidArgument("proof is nil")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewInvalidArgument("length of session id is 0")
	}

	if statement.H1.CurveName() != statement.H2.CurveName() {
		return errs.NewInvalidCurve("this proof system requires both bases to be in the same group")
	}

	if err := dlog.StatementSubgroupMembershipCheck(statement.H1, statement.P1); err != nil {
		return errs.WrapFailed(err, "subgroup membership check failed for P1")
	}
	if err := dlog.StatementSubgroupMembershipCheck(statement.H2, statement.P2); err != nil {
		return errs.WrapFailed(err, "subgroup membership check failed for P2")
	}

	for i := 0; i < RBytes; i++ {
		e_i := proof.E[i]
		z_i := proof.Z[i]
		// step V.2.1
		hashResult, err := h(proof.A1, proof.A2, statement.H1, statement.H2, statement.P1, statement.P2, i, e_i, z_i, uniqueSessionId, extraChallengeElements...)
		if err != nil {
			return errs.WrapFailed(err, "could not produce the hash result")
		}
		if !allZero(hashResult[:]) {
			return errs.NewVerificationFailed("%d iteration not all zero", i)
		}

		// step V.2.2
		ZiH1 := statement.H1.Mul(z_i)
		A1Prime := ZiH1.Add(statement.P1.Mul(e_i.Neg()))
		if !A1Prime.Equal(proof.A1[i]) {
			return errs.NewVerificationFailed("invalid response for A1' in iteration %d", i)
		}

		// step V.2.3
		ZiH2 := statement.H2.Mul(z_i)
		A2Prime := ZiH2.Add(statement.P2.Mul(e_i.Neg()))
		if !A2Prime.Equal(proof.A2[i]) {
			return errs.NewVerificationFailed("invalid response for A2' in iteration %d", i)
		}
	}
	// step V.3
	return nil
}

// h is the hash used in the PoW.
func h(A1, A2 [RBytes]curves.Point, H1, H2, P1, P2 curves.Point, i int, e, z curves.Scalar, sid []byte, extraChellengeElements ...[]byte) ([LBytes]byte, error) {
	curve := H1.Curve()
	message := make([][]byte, (2*RBytes)+9+len(extraChellengeElements)) // 9 = generator + rest of the arguments
	message[0] = curve.Generator().ToAffineCompressed()
	for j := 0; j < RBytes; j++ {
		message[1+j] = A1[j].ToAffineCompressed()
	}
	for j := 0; j < RBytes; j++ {
		message[1+RBytes+j] = A2[j].ToAffineCompressed()
	}
	message[1+2*RBytes] = H1.ToAffineCompressed()
	message[1+2*RBytes+1] = H2.ToAffineCompressed()
	message[1+2*RBytes+2] = P1.ToAffineCompressed()
	message[1+2*RBytes+3] = P2.ToAffineCompressed()
	message[1+2*RBytes+4] = []byte{byte(i)}
	message[1+2*RBytes+5] = e.Bytes()
	message[1+2*RBytes+6] = z.Bytes()
	message[1+2*RBytes+7] = sid
	for j := 0; j < len(extraChellengeElements); j++ {
		message[1+2*RBytes+8+j] = extraChellengeElements[j]
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
