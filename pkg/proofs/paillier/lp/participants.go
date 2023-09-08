package lp

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/encryptions/paillier"
	"github.com/copperexchange/knox-primitives/pkg/proofs/paillier/nthroot"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

const (
	transcriptAppLabel       = "PAILLIER_LP_PROOF"
	transcriptSessionIdLabel = "PaillierLP_SessionId"
	PaillierBitSize          = 1024
)

type Participant struct {
	k          int // security parameter - cheating prover can succeed with probability < 2^(-k)
	round      int
	sessionId  []byte
	transcript transcripts.Transcript
	prng       io.Reader

	_ helper_types.Incomparable
}

type VerifierState struct {
	rootProvers []*nthroot.Prover
	x           []*paillier.CipherText
	y           []*saferith.Nat

	_ helper_types.Incomparable
}

type Verifier struct {
	Participant
	paillierPublicKey *paillier.PublicKey
	state             *VerifierState

	_ helper_types.Incomparable
}

type ProverState struct {
	rootVerifiers []*nthroot.Verifier
	x             []*paillier.CipherText

	_ helper_types.Incomparable
}

type Prover struct {
	Participant
	paillierSecretKey *paillier.SecretKey
	state             *ProverState

	_ helper_types.Incomparable
}

func NewVerifier(k int, paillierPublicKey *paillier.PublicKey, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (verifier *Verifier, err error) {
	err = validateVerifierInputs(k, paillierPublicKey, sessionId, prng)
	if err != nil {
		return nil, errs.NewInvalidArgument("invalid input arguments")
	}

	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)
	return &Verifier{
		Participant: Participant{
			k:          k,
			round:      1,
			sessionId:  sessionId,
			transcript: transcript,
			prng:       prng,
		},
		paillierPublicKey: paillierPublicKey,
		state:             &VerifierState{},
	}, nil
}

func validateVerifierInputs(k int, paillierPublicKey *paillier.PublicKey, sessionId []byte, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if paillierPublicKey == nil {
		return errs.NewInvalidArgument("invalid paillier public key")
	}
	if paillierPublicKey.N.BitLen() < PaillierBitSize {
		return errs.NewInvalidArgument("invalid paillier public key: modulus is too small")
	}
	if k < 1 {
		return errs.NewInvalidArgument("invalid k: %d", k)
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}

func NewProver(k int, paillierSecretKey *paillier.SecretKey, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (prover *Prover, err error) {
	err = validateProverInputs(k, paillierSecretKey, sessionId, prng)
	if err != nil {
		return nil, errs.NewInvalidArgument("invalid input arguments")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptAppLabel)
	}
	transcript.AppendMessages(transcriptSessionIdLabel, sessionId)

	return &Prover{
		Participant: Participant{
			k:          k,
			round:      2,
			sessionId:  sessionId,
			transcript: transcript,
			prng:       prng,
		},
		paillierSecretKey: paillierSecretKey,
		state:             &ProverState{},
	}, nil
}

func validateProverInputs(k int, paillierSecretKey *paillier.SecretKey, sessionId []byte, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if paillierSecretKey == nil {
		return errs.NewInvalidArgument("invalid paillier secret key")
	}
	if k < 1 {
		return errs.NewInvalidArgument("invalid k: %d", k)
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
