package paillierpk

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/paillier"
	"github.com/copperexchange/crypto-primitives-go/pkg/zkp/nthroot"
	"io"
	"math/big"
)

type Participant struct {
	k     int // security parameter - cheating prover can succeed with probability < 2^(-k)
	round int
	prng  io.Reader
}

type VerifierState struct {
	rootProvers []*nthroot.Prover
	x           []paillier.CipherText
	y           []*big.Int
}

type Verifier struct {
	Participant
	paillierPublicKey *paillier.PublicKey
	state             *VerifierState
}

type ProverState struct {
	rootVerifiers []*nthroot.Verifier
	x             []paillier.CipherText
}

type Prover struct {
	Participant
	paillierSecretKey *paillier.SecretKey
	state             *ProverState
}

func NewVerifier(k int, paillierPublicKey *paillier.PublicKey, prng io.Reader) (verifier *Verifier) {
	return &Verifier{
		Participant: Participant{
			k:     k,
			round: 1,
			prng:  prng,
		},
		paillierPublicKey: paillierPublicKey,
		state:             &VerifierState{},
	}
}

func NewProver(k int, paillierSecretKey *paillier.SecretKey, prng io.Reader) (prover *Prover) {
	return &Prover{
		Participant: Participant{
			k:     k,
			round: 2,
			prng:  prng,
		},
		paillierSecretKey: paillierSecretKey,
		state:             &ProverState{},
	}
}
