package pdl

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"io"
	"math/big"
)

type Participant struct {
	c     paillier.CipherText
	pk    *paillier.PublicKey
	bigQ1 curves.Point
	prng  io.Reader
}

type State struct {
	curve *curves.Curve
	q     *big.Int
	q2    *big.Int
	a     *big.Int
	b     *big.Int
}

type VerifierState struct {
	State
	cPrime      *paillier.CipherText
	cBisWitness commitments.Witness
	bigQPrime   curves.Point
	cHat        commitments.Commitment
}

type Verifier struct {
	Participant
	state *VerifierState
}

type ProverState struct {
	State
	alpha          *big.Int
	bigQHat        curves.Point
	bigQHatWitness commitments.Witness
	cBisCommitment commitments.Commitment
}

type Prover struct {
	Participant
	sk    *paillier.SecretKey
	x1    curves.Scalar
	state *ProverState
}

func NewVerifier(cipherText paillier.CipherText, publicKey *paillier.PublicKey, bigQ1 curves.Point, prng io.Reader) (verifier *Verifier, err error) {
	curve, err := curves.GetCurveByName(bigQ1.CurveName())
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "invalid curve %s", bigQ1.CurveName())
	}
	nativeCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "cannot get native curve")
	}
	q := nativeCurve.Params().N
	q2 := new(big.Int).Mul(q, q)

	return &Verifier{
		Participant: Participant{
			c:     cipherText,
			pk:    publicKey,
			bigQ1: bigQ1,
			prng:  prng,
		},
		state: &VerifierState{
			State: State{
				curve: curve,
				q:     q,
				q2:    q2,
			},
		},
	}, nil
}

func NewProver(cipherText paillier.CipherText, secretKey *paillier.SecretKey, x1 curves.Scalar) (verifier *Prover, err error) {
	curve, err := curves.GetCurveByName(x1.Point().CurveName())
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "invalid curve %s", x1.Point().CurveName())
	}
	nativeCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "cannot get native curve")
	}
	q := nativeCurve.Params().N
	q2 := new(big.Int).Mul(q, q)

	return &Prover{
		Participant: Participant{
			c:     cipherText,
			pk:    &secretKey.PublicKey,
			bigQ1: curve.ScalarBaseMult(x1),
		},
		sk: secretKey,
		x1: x1,
		state: &ProverState{
			State: State{
				curve: curve,
				q:     q,
				q2:    q2,
			},
		},
	}, nil
}
