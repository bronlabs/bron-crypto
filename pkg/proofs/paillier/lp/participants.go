package lp

import (
	"fmt"
	"io"

	"github.com/cronokirby/saferith"

	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
	"github.com/bronlabs/krypton-primitives/pkg/base/modular"
	"github.com/bronlabs/krypton-primitives/pkg/indcpa/paillier"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/paillier/nthroots"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/sigma"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts"
	"github.com/bronlabs/krypton-primitives/pkg/transcripts/hagrid"
)

const (
	transcriptLabel = "KRYPTON_PAILLIER_LP-"
	// PaillierBitSize TODO: Should we bump it to 3072 to comply with NIST recommendations?
	PaillierBitSize = 2048
)

type Participant struct {
	// Base participant
	nthRootsProtocol sigma.Protocol[nthroots.Statement, nthroots.Witness, nthroots.Commitment, nthroots.State, nthroots.Response]
	Prng             io.Reader
	Round            int
	SessionId        []byte
	Transcript       transcripts.Transcript

	k int // security parameter - cheating prover can succeed with probability < 2^(-k)

	_ ds.Incomparable
}

func (p *Participant) SoundnessError() int {
	return p.k
}

type VerifierState struct {
	rootsProver *sigma.Prover[nthroots.Statement, nthroots.Witness, nthroots.Commitment, nthroots.State, nthroots.Response]
	x           []*paillier.CipherText
	y           []*saferith.Nat

	_ ds.Incomparable
}

type Verifier struct {
	Participant
	paillierPublicKey *paillier.PublicKey
	state             *VerifierState

	_ ds.Incomparable
}

type ProverState struct {
	rootsVerifier *sigma.Verifier[nthroots.Statement, nthroots.Witness, nthroots.Commitment, nthroots.State, nthroots.Response]
	x             []*paillier.CipherText

	_ ds.Incomparable
}

type Prover struct {
	Participant
	paillierSecretKey *paillier.SecretKey
	state             *ProverState

	_ ds.Incomparable
}

func NewVerifier(k int, paillierPublicKey *paillier.PublicKey, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (verifier *Verifier, err error) {
	if err := validateVerifierInputs(k, paillierPublicKey, sessionId, prng); err != nil {
		return nil, errs.NewArgument("invalid input arguments")
	}

	dst := fmt.Sprintf("%s-%d", transcriptLabel, k)
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	nMod, err := modular.NewFastModulus(paillierPublicKey.N.Nat())
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't get N residue params")
	}

	nthRootsSigmaProtocol, err := nthroots.NewSigmaProtocol(nMod, k, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Nth root protocol")
	}

	return &Verifier{
		Participant: Participant{
			k:                k,
			Round:            1,
			SessionId:        boundSessionId,
			Transcript:       transcript,
			nthRootsProtocol: nthRootsSigmaProtocol,
			Prng:             prng,
		},
		paillierPublicKey: paillierPublicKey,
		state:             &VerifierState{},
	}, nil
}

func validateVerifierInputs(k int, paillierPublicKey *paillier.PublicKey, sessionId []byte, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("invalid session id: %s", sessionId)
	}
	if paillierPublicKey == nil {
		return errs.NewIsNil("invalid paillier public key")
	}
	if paillierPublicKey.N.BitLen() < PaillierBitSize {
		return errs.NewSize("invalid paillier public key: modulus is too small")
	}
	if k < 1 {
		return errs.NewValue("invalid k: %d", k)
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}

func NewProver(k int, paillierSecretKey *paillier.SecretKey, sessionId []byte, transcript transcripts.Transcript, prng io.Reader) (prover *Prover, err error) {
	if err := validateProverInputs(k, paillierSecretKey, sessionId, prng); err != nil {
		return nil, errs.NewArgument("invalid input arguments")
	}

	dst := fmt.Sprintf("%s-%d", transcriptLabel, k)
	if transcript == nil {
		transcript = hagrid.NewTranscript(dst, prng)
	}
	boundSessionId, err := transcript.Bind(sessionId, dst)
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't initialise transcript/sessionId")
	}

	nMod, err := modular.NewFastModulusFromPrimeFactors(paillierSecretKey.P.Nat(), paillierSecretKey.Q.Nat())
	if err != nil {
		return nil, errs.WrapHashing(err, "couldn't get N residue params")
	}

	nthRootsSigmaProtocol, err := nthroots.NewSigmaProtocol(nMod, k, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Nth root protocol")
	}

	return &Prover{
		Participant: Participant{
			k:                k,
			Round:            2,
			SessionId:        boundSessionId,
			Transcript:       transcript,
			nthRootsProtocol: nthRootsSigmaProtocol,
			Prng:             prng,
		},
		paillierSecretKey: paillierSecretKey,
		state:             &ProverState{},
	}, nil
}

func validateProverInputs(k int, paillierSecretKey *paillier.SecretKey, sessionId []byte, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("invalid session id: %s", sessionId)
	}
	if paillierSecretKey == nil {
		return errs.NewIsNil("invalid paillier secret key")
	}
	if k < 1 {
		return errs.NewValue("invalid k: %d", k)
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}
