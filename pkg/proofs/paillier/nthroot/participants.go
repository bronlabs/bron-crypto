package nthroot

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

const (
	transcriptAppLabel       = "PAILLIER_NTH_ROOT_PROOF"
	transcriptSessionIdLabel = "PaillierNthRoot_SessionId"
)

type Participant struct {
	bigN  *saferith.Nat
	x     *saferith.Nat
	round int
	prng  io.Reader

	_ helper_types.Incomparable
}

type ProverState struct {
	bigNSquared *saferith.Modulus
	r           *saferith.Nat

	_ helper_types.Incomparable
}

type Prover struct {
	Participant
	y     *saferith.Nat
	state *ProverState

	_ helper_types.Incomparable
}

type VerifierState struct {
	bigNSquared *saferith.Modulus
	e           *saferith.Nat
	a           *saferith.Nat

	_ helper_types.Incomparable
}

type Verifier struct {
	Participant
	state *VerifierState

	_ helper_types.Incomparable
}

func NewProver(bigN, x, y *saferith.Nat, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (prover *Prover, err error) {
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
			bigNSquared: saferith.ModulusFromNat(new(saferith.Nat).Mul(bigN, bigN, 2*bigN.AnnouncedLen())), // cache bigN^2
		},
	}, nil
}

func NewVerifier(bigN, x *saferith.Nat, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (verifier *Verifier, err error) {
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
			bigNSquared: saferith.ModulusFromNat(new(saferith.Nat).Mul(bigN, bigN, 2*bigN.AnnouncedLen())), // cache bigN^2
		},
	}, nil
}
