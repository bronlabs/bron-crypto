package paillierdlog

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"github.com/copperexchange/crypto-primitives-go/pkg/zkp/paillierrange"
	"io"
	"math/big"
)

type Participant struct {
	pk    *paillier.PublicKey
	bigQ  curves.Point
	round int
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
	rangeVerifier *paillierrange.Verifier
	c             paillier.CipherText
	state         *VerifierState
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
	rangeProver *paillierrange.Prover
	sk          *paillier.SecretKey
	x           curves.Scalar
	state       *ProverState
}

func NewVerifier(xEncrypted paillier.CipherText, publicKey *paillier.PublicKey, bigQ curves.Point, sid []byte, prng io.Reader) (verifier *Verifier, err error) {
	curve, err := curves.GetCurveByName(bigQ.CurveName())
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "invalid curve %s", bigQ.CurveName())
	}
	nativeCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "cannot get native curve")
	}
	q := nativeCurve.Params().N
	q2 := new(big.Int).Mul(q, q)

	rangeVerifier, err := paillierrange.NewVerifier(40, xEncrypted, q, publicKey, sid, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Paillier range verifier")
	}

	return &Verifier{
		Participant: Participant{
			pk:    publicKey,
			bigQ:  bigQ,
			round: 1,
			prng:  prng,
		},
		rangeVerifier: rangeVerifier,
		c:             xEncrypted,
		state: &VerifierState{
			State: State{
				curve: curve,
				q:     q,
				q2:    q2,
			},
		},
	}, nil
}

func NewProver(x curves.Scalar, r *big.Int, secretKey *paillier.SecretKey, sid []byte, prng io.Reader) (verifier *Prover, err error) {
	curve, err := curves.GetCurveByName(x.Point().CurveName())
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "invalid curve %s", x.Point().CurveName())
	}
	nativeCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "cannot get native curve")
	}
	q := nativeCurve.Params().N
	qSquared := new(big.Int).Mul(q, q)

	rangeProver, err := paillierrange.NewProver(40, x.BigInt(), r, q, secretKey, sid, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Paillier range prover")
	}

	return &Prover{
		Participant: Participant{
			pk:    &secretKey.PublicKey,
			bigQ:  curve.ScalarBaseMult(x),
			round: 2,
		},
		rangeProver: rangeProver,
		sk:          secretKey,
		x:           x,
		state: &ProverState{
			State: State{
				curve: curve,
				q:     q,
				q2:    qSquared,
			},
		},
	}, nil
}
