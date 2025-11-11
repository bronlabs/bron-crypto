package lp

import (
	"fmt"
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
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
	// TODO: Should we bump it to 3072 to comply with NIST recommendations?
	PaillierBitSizeN = 2048
)

type Participant[A znstar.ArithmeticPaillier] struct {
	// Base participant
	multiNthRootsProtocol sigma.Protocol[sigand.Statement[*nthroot.Statement[A]], sigand.Witness[*nthroot.Witness[A]], sigand.Commitment[*nthroot.Commitment[A]], sigand.State[*nthroot.State[A]], sigand.Response[*nthroot.Response[A]]]
	Prng                  io.Reader
	Round                 int
	SessionId             network.SID
	Transcript            transcripts.Transcript

	k int // security parameter - cheating prover can succeed with probability < 2^(-k)
}

func (p *Participant[A]) SoundnessError() int {
	return p.k
}

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

type Verifier struct {
	Participant[*modular.SimpleModulus]

	paillierPublicKey *paillier.PublicKey
	enc               *paillier.Encrypter
	state             *VerifierState
}

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

type Prover struct {
	Participant[*modular.OddPrimeSquareFactors]

	paillierSecretKey *paillier.PrivateKey
	state             *ProverState
}

func NewVerifier(sessionId network.SID, k int, pk *paillier.PublicKey, tape transcripts.Transcript, prng io.Reader) (verifier *Verifier, err error) {
	if err := validateVerifierInputs(sessionId, k, pk, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}

	if tape == nil {
		tape = hagrid.NewTranscript(appTranscriptLabel)
	}
	dst := fmt.Sprintf("%s-%d", sessionIdTranscriptLabel, sessionId)
	tape.AppendDomainSeparator(dst)

	nthRootsSigmaProtocol, err := nthroot.NewProtocol(pk.Group(), prng)
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

func validateVerifierInputs(sessionId network.SID, k int, pk *paillier.PublicKey, prng io.Reader) error {
	if len(sessionId) == 0 {
		return errs.NewIsNil("invalid session id: %s", sessionId)
	}
	if pk == nil {
		return errs.NewIsNil("invalid paillier public key")
	}
	// if pk.N().BitLen() < PaillierBitSize {
	// 	return errs.NewSize("invalid paillier public key: modulus is too small")
	// }
	if k < 1 {
		return errs.NewValue("invalid k: %d", k)
	}
	if prng == nil {
		return errs.NewIsNil("prng is nil")
	}
	return nil
}

func NewProver(sessionId network.SID, k int, sk *paillier.PrivateKey, tape transcripts.Transcript, prng io.Reader) (prover *Prover, err error) {
	if err := validateProverInputs(sessionId, k, sk, prng); err != nil {
		return nil, errs.WrapArgument(err, "invalid input arguments")
	}

	if tape == nil {
		tape = hagrid.NewTranscript(appTranscriptLabel)
	}
	dst := fmt.Sprintf("%s-%d", sessionIdTranscriptLabel, sessionId)
	tape.AppendDomainSeparator(dst)

	nthRootsSigmaProtocol, err := nthroot.NewProtocol(sk.Group(), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create Nth root protocol")
	}
	multiNthRootsProtocol, err := sigand.Compose(nthRootsSigmaProtocol, uint(k))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create multi Nth root protocol")
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

func validateProverInputs(sessionId network.SID, k int, sk *paillier.PrivateKey, prng io.Reader) error {
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
