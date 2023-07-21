package paillierrange

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"io"
	"math/big"
)

type Participant struct {
	t    int // security parameter (i.e. a cheating prover can succeed with probability less then 2^(-t)
	prng io.Reader
}

type State struct {
	q *big.Int
	l *big.Int
}

type ProverState struct {
	State
	esidCommitment commitments.Commitment
	w1             []*big.Int
	r1             []*big.Int
	w2             []*big.Int
	r2             []*big.Int
}

type Prover struct {
	Participant
	x     curves.Scalar
	c     paillier.CipherText
	r     *big.Int
	sk    *paillier.SecretKey
	state *ProverState
}

type VerifierState struct {
	State
	e           *big.Int
	esidWitness commitments.Witness
	c1          []paillier.CipherText
	c2          []paillier.CipherText
}

type Verifier struct {
	Participant
	c     paillier.CipherText
	pk    *paillier.PublicKey
	sid   []byte
	state *VerifierState
}

func NewProver(t int, x curves.Scalar, xEncrypted paillier.CipherText, r *big.Int, sk *paillier.SecretKey, prng io.Reader) (prover *Prover, err error) {
	curve, err := curves.GetCurveByName(x.Point().CurveName())
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "invalid curve %s", x.Point().CurveName())
	}
	nativeCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "cannot get native curve")
	}
	q := nativeCurve.Params().N
	l := new(big.Int).Div(q, big.NewInt(3)) // l = floor(q/3)
	// TODO: should it be encrypted with the same r?
	lNegEncrypted, _, err := sk.Encrypt(new(big.Int).Neg(l))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt l")
	}
	lScalar, err := curve.NewScalar().SetBigInt(l)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create scalar")
	}
	x2 := x.Sub(lScalar)
	if x2.BigInt().Cmp(l) > 0 {
		return nil, errs.NewInvalidArgument("x not in the range [q/3, 2q/3]")
	}
	c, err := sk.Add(xEncrypted, lNegEncrypted)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot add paillier ciphertexts")
	}

	return &Prover{
		Participant: Participant{
			t:    t,
			prng: prng,
		},
		x:  x2,
		c:  c,
		r:  r,
		sk: sk,
		state: &ProverState{
			State: State{
				q: q,
				l: l,
			},
		},
	}, nil
}

func NewVerifier(t int, xEncrypted paillier.CipherText, curve curves.Curve, pk *paillier.PublicKey, sid []byte, prng io.Reader) (verifier *Verifier, err error) {
	nativeCurve, err := curve.ToEllipticCurve()
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "cannot get native curve")
	}
	q := nativeCurve.Params().N
	l := new(big.Int).Div(q, big.NewInt(3)) // l = floor(q/3)
	// TODO: should it be encrypted with the same r?
	lNegEncrypted, _, err := pk.Encrypt(new(big.Int).Neg(l))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt l")
	}
	c, err := pk.Add(xEncrypted, lNegEncrypted)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt l")
	}

	return &Verifier{
		Participant: Participant{
			t:    t,
			prng: prng,
		},
		c:   c,
		pk:  pk,
		sid: sid,
		state: &VerifierState{
			State: State{
				q: q,
				l: l,
			},
		},
	}, nil
}
