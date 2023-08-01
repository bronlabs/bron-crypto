package nthroot

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/transcript"
	"github.com/copperexchange/crypto-primitives-go/pkg/transcript/merlin"
	"io"
	"math/big"
)

const (
	transcriptAppLabel       = "PAILLIER_NTH_ROOT_PROOF"
	transcriptSessionIdLabel = "PaillierNthRoot_SessionId"
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

func NewProver(bigN *big.Int, x *big.Int, y *big.Int, sessionId []byte, transcript transcript.Transcript, prng io.Reader) (prover *Prover, err error) {
	if sessionId == nil || len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if transcript == nil {
		transcript = merlin.NewTranscript(transcriptAppLabel)
	}
	err = transcript.AppendMessage([]byte(transcriptSessionIdLabel), sessionId)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot write to transcript")
	}

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

func NewVerifier(bigN *big.Int, x *big.Int, sessionId []byte, transcript transcript.Transcript, prng io.Reader) (verifier *Verifier, err error) {
	if sessionId == nil || len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if transcript == nil {
		transcript = merlin.NewTranscript(transcriptAppLabel)
	}
	err = transcript.AppendMessage([]byte(transcriptSessionIdLabel), sessionId)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot write to transcript")
	}

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
