package nthroot

import (
	"io"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
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

func NewProver(bigN, x, y *big.Int, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (prover *Prover, err error) {
	if len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptAppLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

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

func NewVerifier(bigN, x *big.Int, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (verifier *Verifier, err error) {
	if len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptAppLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

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
