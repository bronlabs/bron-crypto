package fischlin

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/merlin"
	"golang.org/x/crypto/sha3"
)

const (
	domainSeparationLabel = "COPPER_ZKPOK_DLOG_FISCHLIN-"
	Lambda                = 128
	L                     = 1
	R                     = Lambda / L
	// 3 is ceil(log(Lambda=128)). If you change the security paramter, you have to change this one as well.
	T = 3 * L
)

type Prover struct {
	uniqueSessionId []byte
	transcript      transcripts.Transcript
	prng            io.Reader
	BasePoint       curves.Point
}

type Proof struct {
	A [R]curves.Point
	E [R]curves.Scalar
	Z [R]curves.Point
}

type Statement = curves.Point

// NewProver generates a `Prover` object, ready to generate Schnorr proofs on any given point.
func NewProver(basePoint curves.Point, uniqueSessionId []byte, transcript transcripts.Transcript, prng io.Reader) (*Prover, error) {
	if basePoint == nil {
		return nil, errs.NewInvalidArgument("basepoint can't be nil")
	}
	if basePoint.IsIdentity() {
		return nil, errs.NewIsIdentity("basepoint is identity")
	}
	if prng == nil {
		return nil, errs.NewIsNil("prng")
	}
	if transcript == nil {
		transcript = merlin.NewTranscript(domainSeparationLabel)
	}
	transcript.AppendMessages("Randomized Fischlin proof", uniqueSessionId)
	return &Prover{
		BasePoint:       basePoint,
		uniqueSessionId: uniqueSessionId,
		transcript:      transcript,
		prng:            prng,
	}, nil
}

// func initializeShake(sid []byte, A [R]curves.Point) (sha3.ShakeHash, error) {
// 	shake := sha3.NewCShake256(sid, []byte("unique session id"))
// 	for _, A_i := range A {
// 		if _, err := shake.Write(A_i.ToAffineCompressed()); err != nil {
// 			return nil, errs.WrapFailed(err, "A_i write to shake")
// 		}
// 	}
// 	return shake, nil
// }

func H(A [R]curves.Point, i int, e curves.Scalar, z curves.Point) [L]byte {
	message := [R + 3][]byte{}
	for i := 0; i < R; i++ {
		message[i] = A[i].ToAffineCompressed()
	}
	message[R] = []byte{byte(i)}
	message[R+1] = e.Bytes()
	message[R+2] = z.ToAffineCompressed()
	hashed, _ := hashing.Hash(sha3.New256, message[:]...)
	output := [L]byte{}
	copy(output[:], hashed[:L])
	return output
}

func allZero(xs []byte) bool {
	for _, x := range xs {
		if x != byte(0) {
			return false
		}
	}
	return true
}

func sample(E_i [][T]byte, prng io.Reader) ([T]byte, error) {
	e_i := [T]byte{}
	found := false
SAMPLE:
	for !found {
		if _, err := prng.Read(e_i[:]); err != nil {
			return [T]byte{}, errs.WrapFailed(err, "could not read random bytes")
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

func (p *Prover) Prove(x curves.Scalar) (*Proof, Statement, error) {
	curve, err := curves.GetCurveByName(p.BasePoint.CurveName())
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not get curve by name")
	}
	statement := p.BasePoint.Mul(x)
	p.transcript.AppendPoints("statement", statement)

	tprng, err := p.transcript.NewReader("witness", x.Bytes(), p.prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not construct transcript based prng")
	}

	a := [R]curves.Scalar{}
	A := [R]curves.Point{}
	for i := 0; i < R; i++ {
		a[i] = curve.Scalar.Random(tprng)
		A[i] = p.BasePoint.Mul(a[i])
	}
	e := [R]curves.Scalar{}
	z := [R]curves.Point{}

	for i := 0; i < R; i++ {
		E_i := [][T]byte{}
		solvedHash := false
		for !solvedHash {
			e_i_bytes, err := sample(E_i, tprng)
			if err != nil {
				return nil, nil, errs.WrapFailed(err, "sampling")
			}
			e_i := curve.Scalar.Hash(e_i_bytes[:])

			z_i := a[i].Add(x.Mul(e_i))
			Z_i := p.BasePoint.Mul(z_i)
			hashResult := H(A, i, e_i, Z_i)
			if allZero(hashResult[:]) {
				solvedHash = true
				e[i] = e_i
				z[i] = Z_i
			} else {
				E_i = append(E_i, e_i_bytes)
			}
		}
	}

	return &Proof{
		A: A,
		E: e,
		Z: z,
	}, statement, nil
}

func Verify(basePoint curves.Point, statement Statement, proof *Proof, uniqueSessionId []byte) error {
	for i := 0; i < R; i++ {
		e_i := proof.E[i]
		Z_i := proof.Z[i]
		hashResult := H(proof.A, i, e_i, Z_i)
		if !allZero(hashResult[:]) {
			return errs.NewVerificationFailed("%d iteration not all zero", i)
		}

		APrime := Z_i.Add(statement.Mul(e_i.Neg()))
		if !APrime.Equal(proof.A[i]) {
			return errs.NewVerificationFailed("invalid response for iteration %d", i)
		}
	}
	return nil
}
