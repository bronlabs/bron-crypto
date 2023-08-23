package lp

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/paillier"
	"github.com/copperexchange/knox-primitives/pkg/proofs/paillier/nthroot"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

const (
	transcriptAppLabel       = "PAILLIER_LP_PROOF"
	transcriptSessionIdLabel = "PaillierLP_SessionId"
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
	x           []paillier.CipherText
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
	x             []paillier.CipherText

	_ helper_types.Incomparable
}

type Prover struct {
	Participant
	paillierSecretKey *paillier.SecretKey
	state             *ProverState

	_ helper_types.Incomparable
}

func NewVerifier(k int, paillierPublicKey *paillier.PublicKey, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (verifier *Verifier, err error) {
	if len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", sessionId)
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript(transcriptAppLabel)
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

func NewProver(k int, paillierSecretKey *paillier.SecretKey, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (prover *Prover, err error) {
	if len(sessionId) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", sessionId)
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
