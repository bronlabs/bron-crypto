package lp

import (
	"encoding/hex"
	"fmt"
	"io"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/modular"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/proofs/paillier/nthroot"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compose/sigand"
)

const (
	appTranscriptLabel       = "BRON_CRYPTO_PAILLIER_LP-"
	sessionIDTranscriptLabel = "BRON_CRYPTO_PAILLIER_LP_SESSION_ID"
)

// Participant holds a common state for the LP protocol participants.
type Participant[A znstar.ArithmeticPaillier] struct {
	ctx       *session.Context
	copartyID sharing.ID
	// Base participant
	multiNthRootsProtocol sigma.Protocol[sigand.Statement[*nthroot.Statement[A]], sigand.Witness[*nthroot.Witness[A]], sigand.Commitment[*nthroot.Commitment[A]], sigand.State[*nthroot.State[A]], sigand.Response[*nthroot.Response[A]]]
	prng                  io.Reader
	round                 int

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
func NewVerifier(ctx *session.Context, k int, pk *paillier.PublicKey, prng io.Reader) (verifier *Verifier, err error) {
	if err := validateVerifierInputs(ctx, k, pk, prng); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid input arguments")
	}

	copartyID := slices.Collect(ctx.OtherPartiesOrdered())[0]
	sid := ctx.SessionID()
	dst := fmt.Sprintf("%s-%s", sessionIDTranscriptLabel, hex.EncodeToString(sid[:]))
	ctx.Transcript().AppendDomainSeparator(dst)

	nthRootsSigmaProtocol, err := nthroot.NewProtocol(pk.Group())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Nth root protocol")
	}
	multiNthRootsProtocol, err := sigand.Compose(nthRootsSigmaProtocol, uint(k))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create multi Nth root protocol")
	}
	enc, err := paillier.NewScheme().Encrypter()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create paillier encrypter")
	}

	return &Verifier{
		Participant: Participant[*modular.SimpleModulus]{
			ctx:                   ctx,
			copartyID:             copartyID,
			round:                 1,
			prng:                  prng,
			k:                     k,
			multiNthRootsProtocol: multiNthRootsProtocol,
		},
		paillierPublicKey: pk,
		enc:               enc,
		state: &VerifierState{
			rootsProver: nil,
			x:           nil,
			y:           nil,
		},
	}, nil
}

func validateVerifierInputs(ctx *session.Context, k int, pk *paillier.PublicKey, prng io.Reader) error {
	if ctx == nil {
		return ErrInvalidArgument.WithMessage("ctx is nil")
	}
	if ctx.Quorum().Size() != 2 {
		return ErrInvalidArgument.WithMessage("invalid quorum size")
	}
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
func NewProver(ctx *session.Context, k int, sk *paillier.PrivateKey, prng io.Reader) (prover *Prover, err error) {
	if err := validateProverInputs(ctx, k, sk, prng); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid input arguments")
	}

	copartyID := slices.Collect(ctx.OtherPartiesOrdered())[0]
	sid := ctx.SessionID()
	dst := fmt.Sprintf("%s-%s", sessionIDTranscriptLabel, hex.EncodeToString(sid[:]))
	ctx.Transcript().AppendDomainSeparator(dst)

	nthRootsSigmaProtocol, err := nthroot.NewProtocol(sk.Group())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Nth root protocol")
	}
	multiNthRootsProtocol, err := sigand.Compose(nthRootsSigmaProtocol, uint(k))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create multi Nth root protocol")
	}

	return &Prover{
		Participant: Participant[*modular.OddPrimeSquareFactors]{
			ctx:                   ctx,
			copartyID:             copartyID,
			prng:                  prng,
			round:                 2,
			k:                     k,
			multiNthRootsProtocol: multiNthRootsProtocol,
		},
		paillierSecretKey: sk,
		state: &ProverState{
			rootsVerifier: nil,
			x:             nil,
		},
	}, nil
}

func validateProverInputs(ctx *session.Context, k int, sk *paillier.PrivateKey, prng io.Reader) error {
	if ctx == nil {
		return ErrInvalidArgument.WithMessage("ctx is nil")
	}
	if ctx.Quorum().Size() != 2 {
		return ErrInvalidArgument.WithMessage("invalid quorum size")
	}
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
