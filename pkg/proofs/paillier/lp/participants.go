package lp

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/nthroot"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compose/sigand"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
)

const (
	appTranscriptLabel       = "BRON_CRYPTO_PAILLIER_LP-"
	sessionIdTranscriptLabel = "BRON_CRYPTO_PAILLIER_LP_SESSION_ID"
)

// Participant holds a common state for the LP protocol participants.
type Participant[A znstar.ArithmeticPaillier] struct {
	// Base participant
	multiNthRootsProtocol sigma.Protocol[sigand.Statement[*nthroot.Statement[A]], sigand.Witness[*nthroot.Witness[A]], sigand.Commitment[*nthroot.Commitment[A]], sigand.State[*nthroot.State[A]], sigand.Response[*nthroot.Response[A]]]
	Prng                  io.Reader
	Round                 int
	SessionId             network.SID
	Transcript            transcripts.Transcript

	k int // security parameter - cheating prover can succeed with probability < 2^(-k)
}

// SoundnessError returns the protocol soundness parameter.
func (p *Participant[A]) SoundnessError() int {
	return p.k
}

// VerifierState tracks the verifier's internal state across rounds.
type VerifierState struct {
	rootsProver *sigma.Prover[
		sigand.Statement[*nthroot.Statement[*modular.SimpleModulus]],
		sigand.Witness[*nthroot.Witness[*modular.SimpleModulus]],
		sigand.Commitment[*nthroot.Commitment[*modular.SimpleModulus]],
		sigand.State[*nthroot.State[*modular.SimpleModulus]],
		sigand.Response[*nthroot.Response[*modular.SimpleModulus]],
	]
	x sigand.Statement[*nthroot.Statement[*modular.SimpleModulus]]
	y sigand.Witness[*nthroot.Witness[*modular.SimpleModulus]]
}

// Verifier runs the LP verifier role.
type Verifier struct {
	Participant[*modular.SimpleModulus]

	paillierPublicKey *paillier.PublicKey
	enc               *paillier.Encrypter
	state             *VerifierState
}

// ProverState tracks the prover's internal state across rounds.
type ProverState struct {
	rootsVerifier *sigma.Verifier[
		sigand.Statement[*nthroot.Statement[*modular.OddPrimeSquareFactors]],
		sigand.Witness[*nthroot.Witness[*modular.OddPrimeSquareFactors]],
		sigand.Commitment[*nthroot.Commitment[*modular.OddPrimeSquareFactors]],
		sigand.State[*nthroot.State[*modular.OddPrimeSquareFactors]],
		sigand.Response[*nthroot.Response[*modular.OddPrimeSquareFactors]],
	]
	x sigand.Statement[*nthroot.Statement[*modular.OddPrimeSquareFactors]]
}

// Prover runs the LP prover role.
type Prover struct {
	Participant[*modular.OddPrimeSquareFactors]

	paillierSecretKey *paillier.PrivateKey
	state             *ProverState
}

// NewVerifier constructs a verifier instance for the LP protocol.
func NewVerifier(sessionId network.SID, k int, pk *paillier.PublicKey, tape transcripts.Transcript, prng io.Reader) (verifier *Verifier, err error) {
	if err := validateVerifierInputs(k, pk, prng); err != nil {
		return nil, errs2.Wrap(err).WithMessage("invalid input arguments")
	}

	if tape == nil {
		tape = hagrid.NewTranscript(appTranscriptLabel)
	}
	dst := fmt.Sprintf("%s-%d", sessionIdTranscriptLabel, sessionId)
	tape.AppendDomainSeparator(dst)

	nthRootsSigmaProtocol, err := nthroot.NewProtocol(pk.Group(), prng)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create Nth root protocol")
	}
	multiNthRootsProtocol, err := sigand.Compose(nthRootsSigmaProtocol, uint(k))
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create multi Nth root protocol")
	}
	enc, err := paillier.NewScheme().Encrypter()
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create paillier encrypter")
	}

	return &Verifier{
		Participant: Participant[*modular.SimpleModulus]{
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

func validateVerifierInputs(k int, pk *paillier.PublicKey, prng io.Reader) error {
	if pk == nil {
		return ErrInvalidArgument.WithMessage("paillier public key is nil")
	}
	if k < 1 {
		return ErrInvalidArgument.WithMessage("invalid k: %d (must be positive)", k)
	}
	if prng == nil {
		return ErrInvalidArgument.WithMessage("prng is nil")
	}
	return nil
}

// NewProver constructs a prover instance for the LP protocol.
func NewProver(sessionId network.SID, k int, sk *paillier.PrivateKey, tape transcripts.Transcript, prng io.Reader) (prover *Prover, err error) {
	if err := validateProverInputs(k, sk, prng); err != nil {
		return nil, errs2.Wrap(err).WithMessage("invalid input arguments")
	}

	if tape == nil {
		tape = hagrid.NewTranscript(appTranscriptLabel)
	}
	dst := fmt.Sprintf("%s-%d", sessionIdTranscriptLabel, sessionId)
	tape.AppendDomainSeparator(dst)

	nthRootsSigmaProtocol, err := nthroot.NewProtocol(sk.Group(), prng)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create Nth root protocol")
	}
	multiNthRootsProtocol, err := sigand.Compose(nthRootsSigmaProtocol, uint(k))
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create multi Nth root protocol")
	}

	return &Prover{
		Participant: Participant[*modular.OddPrimeSquareFactors]{
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

func validateProverInputs(k int, sk *paillier.PrivateKey, prng io.Reader) error {
	if sk == nil {
		return ErrInvalidArgument.WithMessage("paillier secret key is nil")
	}
	if k < 1 {
		return ErrInvalidArgument.WithMessage("invalid k: %d (must be positive)", k)
	}
	if prng == nil {
		return ErrInvalidArgument.WithMessage("prng is nil")
	}
	return nil
}
