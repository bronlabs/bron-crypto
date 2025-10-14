package lp

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/nthroots"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compose/sigand"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

const (
	appTranscriptLabel       = "BRON_CRYPTO_PAILLIER_LP-"
	sessionIdTranscriptLabel = "BRON_CRYPTO_PAILLIER_LP_SESSION_ID"
	// TODO: Should we bump it to 3072 to comply with NIST recommendations?
	PaillierBitSize = 2048
)

type Participant struct {
	// Base participant
	multiNthRootsProtocol sigma.Protocol[sigand.Statement[*nthroots.Statement], sigand.Witness[*nthroots.Witness], sigand.Commitment[*nthroots.Commitment], sigand.State[*nthroots.State], sigand.Response[*nthroots.Response]]
	Prng                  io.Reader
	Round                 int
	SessionId             []byte
	Transcript            transcripts.Transcript

	k int // security parameter - cheating prover can succeed with probability < 2^(-k)
}

func (p *Participant) SoundnessError() int {
	return p.k
}

type VerifierState struct {
	rootsProver *sigma.Prover[sigand.Statement[*nthroots.Statement], sigand.Witness[*nthroots.Witness], sigand.Commitment[*nthroots.Commitment], sigand.State[*nthroots.State], sigand.Response[*nthroots.Response]]
	// x           []*paillier.Ciphertext
	// y           []*paillier.Nonce
	x sigand.Statement[*nthroots.Statement]
	y sigand.Witness[*nthroots.Witness]
}

type Verifier struct {
	Participant
	paillierPublicKey *paillier.PublicKey
	enc               *paillier.Encrypter
	state             *VerifierState
}

type ProverState struct {
	rootsVerifier *sigma.Verifier[sigand.Statement[*nthroots.Statement], sigand.Witness[*nthroots.Witness], sigand.Commitment[*nthroots.Commitment], sigand.State[*nthroots.State], sigand.Response[*nthroots.Response]]
	// x             []*paillier.Ciphertext
	x sigand.Statement[*nthroots.Statement]
}

type Prover struct {
	Participant
	paillierSecretKey *paillier.PrivateKey
	state             *ProverState
}

func NewVerifier(k int, pk *paillier.PublicKey, sessionId []byte, tape transcripts.Transcript, prng io.Reader) (verifier *Verifier, err error) {
	if err := validateVerifierInputs(k, pk, sessionId, prng); err != nil {
		return nil, errs.NewArgument("invalid input arguments")
	}

	if tape == nil {
		tape = hagrid.NewTranscript(appTranscriptLabel)
	}
	dst := fmt.Sprintf("%s-%d", sessionIdTranscriptLabel, sessionId)
	tape.AppendDomainSeparator(dst)

	nthRootsSigmaProtocol, err := nthroots.NewSigmaProtocol(pk.Group(), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Nth root protocol")
	}
	multiNthRootsProtocol, err := sigand.Compose(nthRootsSigmaProtocol, uint(k))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create multi Nth root protocol")
	}
	enc, err := paillier.NewScheme().Encrypter()
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create paillier encrypter")
	}

	return &Verifier{
		Participant: Participant{
			k:                     k,
			Round:                 1,
			SessionId:             sessionId,
			Transcript:            tape,
			multiNthRootsProtocol: multiNthRootsProtocol,
			Prng:                  prng,
		},
		paillierPublicKey: pk,
		enc:               enc,
		state:             &VerifierState{},
	}, nil
}

func validateVerifierInputs(k int, pk *paillier.PublicKey, sessionId []byte, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("invalid session id: %s", sessionId)
	}
	if pk == nil {
		return errs.NewIsNil("invalid paillier public key")
	}
	if pk.N().BitLen() < PaillierBitSize {
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

func NewProver(k int, sk *paillier.PrivateKey, sessionId []byte, tape transcripts.Transcript, prng io.Reader) (prover *Prover, err error) {
	if err := validateProverInputs(k, sk, sessionId, prng); err != nil {
		return nil, errs.NewArgument("invalid input arguments")
	}

	if tape == nil {
		tape = hagrid.NewTranscript(appTranscriptLabel)
	}
	dst := fmt.Sprintf("%s-%d", sessionIdTranscriptLabel, sessionId)
	tape.AppendDomainSeparator(dst)

	nthRootsSigmaProtocol, err := nthroots.NewSigmaProtocol(sk.Group(), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Nth root protocol")
	}
	multiNthRootsProtocol, err := sigand.Compose(nthRootsSigmaProtocol, uint(k))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create multi Nth root protocol")
	}

	return &Prover{
		Participant: Participant{
			k:                     k,
			Round:                 2,
			SessionId:             sessionId,
			Transcript:            tape,
			multiNthRootsProtocol: multiNthRootsProtocol,
			Prng:                  prng,
		},
		paillierSecretKey: sk,
		state:             &ProverState{},
	}, nil
}

func validateProverInputs(k int, sk *paillier.PrivateKey, sessionId []byte, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("invalid session id: %s", sessionId)
	}
	if sk == nil {
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
