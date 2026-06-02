package dkg

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/dh/dhc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/canetti"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/prm"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	"github.com/bronlabs/errs-go/errs"
)

const (
	domainSeparator = "BRON_CRYPTO_DKG_CGGMP21-"
	ckLabel         = "BRON_CRYPTO_DKG_CGGMP21_CK-"
)

type Participant[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	curve              ecdsa.Curve[P, B, S]
	canettiParticipant *canetti.Participant[P, S]
	round              network.Round
	state              state[P, B, S]
}

type state[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	paillierSecretKey     *paillier.SecretKey
	ringPedersenSecretKey *intcom.TrapdoorKey

	commitmentKey *hashcom.CommitmentKey

	prm             *fiatshamir.Protocol[*prm.Statement, *prm.Witness, *prm.Commitment, *prm.State, *prm.Response]
	additiveSharing *additive.Scheme[S]
	schnorrScheme   *batch_schnorr.Protocol[P, S]

	psi_i compiler.NIZKPoKProof
	Ai    *batch_schnorr.Commitment[P, S]
	tau   *batch_schnorr.State[S]
	rid_i []byte
	u_i   hashcom.Witness

	dhPrivateKeys map[sharing.ID]*dhc.ExtendedPrivateKey[S]
	Yi            map[sharing.ID]*dhc.PublicKey[P, B, S]

	sharesOfZero map[sharing.ID]*additive.Share[S]
	Xi           map[sharing.ID]P
}

func NewParticipant[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, accessStructure accessstructures.Monotone, curve ecdsa.Curve[P, B, S], prng io.Reader) (*Participant[P, B, S], error) {
	if ctx == nil {
		return nil, cggmp21.ErrNil.WithMessage("session context is nil")
	}
	ctx.Transcript().AppendDomainSeparator(domainSeparator)
	canettiParticipant, err := canetti.NewParticipant(ctx, accessStructure, curve, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create DKG participant")
	}

	prmgInteractiveProtocol, err := prm.NewProtocol(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create PRM protocol")
	}
	prmfs, err := fiatshamir.NewCompiler(prmgInteractiveProtocol)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Fiat-Shamir compiler")
	}

	additiveAccessStructure, err := unanimity.NewUnanimityAccessStructure(ctx.Quorum())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create minimal qualified access structure")
	}
	additiveSharing, err := additive.NewScheme(curve.ScalarField(), additiveAccessStructure)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create additive sharing scheme")
	}

	schnorrScheme, err := batch_schnorr.NewProtocol(int(canettiParticipant.SharingScheme().MSP().D()), curve, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create ZK scheme")
	}

	commitmentKey, err := hashcom.ExtractCommitmentKey(ctx.Transcript(), ckLabel)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not extract commitment key from transcript")
	}

	return &Participant[P, B, S]{
		curve:              curve,
		canettiParticipant: canettiParticipant,
		round:              1,
		state: state[P, B, S]{
			prm:             prmfs,
			additiveSharing: additiveSharing,
			schnorrScheme:   schnorrScheme,
			commitmentKey:   commitmentKey,

			dhPrivateKeys: make(map[sharing.ID]*dhc.ExtendedPrivateKey[S], ctx.Quorum().Size()),
			Yi:            make(map[sharing.ID]*dhc.PublicKey[P, B, S], ctx.Quorum().Size()),

			sharesOfZero: make(map[sharing.ID]*additive.Share[S], ctx.Quorum().Size()),
			Xi:           make(map[sharing.ID]P, ctx.Quorum().Size()),

			rid_i: make([]byte, curve.ElementSize()),
		},
	}, nil
}

func (p *Participant[P, B, S]) Kappa() int {
	return p.curve.ElementSize()
}

// PRNG returns the randomness source of the participant.
func (p *Participant[P, B, S]) PRNG() io.Reader {
	return p.canettiParticipant.PRNG()
}

// Ctx returns the session context of the participant.
func (p *Participant[P, B, S]) Ctx() *session.Context {
	return p.canettiParticipant.Ctx()
}

// SharingID returns the sharing identifier of the local participant.
func (p *Participant[P, B, S]) SharingID() sharing.ID {
	return p.canettiParticipant.SharingID()
}
