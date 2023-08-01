package paillierrange

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"io"
	"math/big"
)

type Participant struct {
	t     int // security parameter (i.e. a cheating prover can succeed with probability less then 2^(-t))
	q     *big.Int
	l     *big.Int
	round int
	sid   []byte
	prng  io.Reader
}

type ProverState struct {
	esidCommitment commitments.Commitment
	w1             []*big.Int
	r1             []*big.Int
	w2             []*big.Int
	r2             []*big.Int
}

type Prover struct {
	Participant
	x     *big.Int
	r     *big.Int
	sk    *paillier.SecretKey
	state *ProverState
}

type VerifierState struct {
	e           *big.Int
	esidWitness commitments.Witness
	c1          []paillier.CipherText
	c2          []paillier.CipherText
}

type Verifier struct {
	Participant
	c     paillier.CipherText
	pk    *paillier.PublicKey
	state *VerifierState
}

func NewProver(t int, q *big.Int, sid []byte, sk *paillier.SecretKey, x *big.Int, r *big.Int, prng io.Reader) (prover *Prover, err error) {
	// 2.i. computes l = ceil(q/3)
	l := new(big.Int).Div(new(big.Int).Add(q, big.NewInt(2)), big.NewInt(3)) // l = ceil(q/3)

	// 2.ii. computes c = c (-) l
	xMinusQThird := new(big.Int).Sub(x, l)

	return &Prover{
		Participant: Participant{
			t:     t,
			q:     q,
			l:     l,
			round: 2,
			sid:   sid,
			prng:  prng,
		},
		x:     xMinusQThird,
		r:     r,
		sk:    sk,
		state: &ProverState{},
	}, nil
}

func NewVerifier(t int, q *big.Int, sid []byte, pk *paillier.PublicKey, xEncrypted paillier.CipherText, prng io.Reader) (verifier *Verifier, err error) {
	// 1.i. computes l = ceil(q/3)
	l := new(big.Int).Div(new(big.Int).Add(q, big.NewInt(2)), big.NewInt(3)) // l = ceil(q/3)

	// 1.ii. computes c = c (-) l
	cMinusQThirdEncrypted, err := pk.SubPlain(xEncrypted, l)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot encrypt l")
	}

	return &Verifier{
		Participant: Participant{
			t:     t,
			q:     q,
			l:     l,
			round: 1,
			sid:   sid,
			prng:  prng,
		},
		c:     cMinusQThirdEncrypted,
		pk:    pk,
		state: &VerifierState{},
	}, nil
}
