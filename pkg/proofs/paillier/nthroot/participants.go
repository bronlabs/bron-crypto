package nthroot

import (
	"io"
	"math/big"
)

type Participant struct {
	bigN  *big.Int
	x     *big.Int
	round int
	prng  io.Reader
}

type ProverState struct {
	bigNSquared *big.Int
	r           *big.Int
}

type Prover struct {
	Participant
	y     *big.Int
	state *ProverState
}

type VerifierState struct {
	bigNSquared *big.Int
	e           *big.Int
	a           *big.Int
}

type Verifier struct {
	Participant
	state *VerifierState
}

func NewProver(bigN *big.Int, x *big.Int, y *big.Int, prng io.Reader) (prover *Prover, err error) {
	return &Prover{
		Participant: Participant{
			bigN:  bigN,
			x:     x,
			round: 1,
			prng:  prng,
		},
		y: y,
		state: &ProverState{
			bigNSquared: new(big.Int).Mul(bigN, bigN), // cache bigN^2
		},
	}, nil
}

func NewVerifier(bigN *big.Int, x *big.Int, prng io.Reader) (verifier *Verifier, err error) {
	return &Verifier{
		Participant: Participant{
			bigN:  bigN,
			x:     x,
			round: 2,
			prng:  prng,
		},
		state: &VerifierState{
			bigNSquared: new(big.Int).Mul(bigN, bigN), // cache bigN^2
		},
	}, nil
}
