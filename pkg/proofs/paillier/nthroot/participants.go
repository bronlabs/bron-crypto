package nthroot

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton/pkg/base/errs"
	"github.com/copperexchange/krypton/pkg/base/types"
	"github.com/copperexchange/krypton/pkg/transcripts"
	"github.com/copperexchange/krypton/pkg/transcripts/hagrid"
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

	_ types.Incomparable
}

type ProverState struct {
	bigNSquared *saferith.Modulus
	r           *saferith.Nat

	_ types.Incomparable
}

type Prover struct {
	Participant
	y     *saferith.Nat
	state *ProverState

	_ types.Incomparable
}

type VerifierState struct {
	bigNSquared *saferith.Modulus
	e           *saferith.Nat
	a           *saferith.Nat

	_ types.Incomparable
}

type Verifier struct {
	Participant
	state *VerifierState

	_ types.Incomparable
}

func NewProver(bigN, x, y *saferith.Nat, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (prover *Prover, err error) {
	err = validateProverInputs(bigN, x, y, sessionId, prng)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid input arguments")
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

func validateProverInputs(bigN, x, y *saferith.Nat, sessionId []byte, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("session id is empty")
	}
	if x == nil {
		return errs.NewIsNil("x is nil")
	}
	if y == nil {
		return errs.NewIsNil("y is nil")
	}
	if bigN == nil {
		return errs.NewIsNil("bigN is nil")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}

func NewVerifier(bigN, x *saferith.Nat, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (verifier *Verifier, err error) {
	err = validateVerifierInputs(bigN, x, sessionId, prng)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "invalid input arguments")
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

func validateVerifierInputs(bigN, x *saferith.Nat, sessionId []byte, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if x == nil {
		return errs.NewIsNil("x is nil")
	}
	if bigN == nil {
		return errs.NewIsNil("bigN is nil")
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
