package paillierrange

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"io"
	"math/big"
)

type Participant struct {
	t     int // security parameter (i.e. a cheating prover can succeed with probability less then 2^(-t)
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

func NewProver(t int, x *big.Int, r *big.Int, q *big.Int, sk *paillier.SecretKey, sid []byte, prng io.Reader) (prover *Prover, err error) {
	l := new(big.Int).Div(q, big.NewInt(3)) // l = floor(q/3)
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

func NewVerifier(t int, xEncrypted paillier.CipherText, q *big.Int, pk *paillier.PublicKey, sid []byte, prng io.Reader) (verifier *Verifier, err error) {
	l := new(big.Int).Div(q, big.NewInt(3)) // l = floor(q/3)
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
