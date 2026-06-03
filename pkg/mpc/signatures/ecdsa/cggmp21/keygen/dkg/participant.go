package dkg

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/dh/dhc"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/blummod"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/fac"
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
	proverIDLabel   = "BRON_CRYPTO_DKG_CGGMP21_PROVER_ID-"
	ridLabel        = "BRON_CRYPTO_DKG_CGGMP21_RID-"
)

type Participant[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ctx       *session.Context
	curve     ecdsa.Curve[P, B, S]
	baseShard *mpc.BaseShard[P, S]
	prng      io.Reader
	round     network.Round
	state     state[P, B, S]
}

type state[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	proverCtx    *session.Context
	verifierCtxs map[sharing.ID]*session.Context

	paillierSecretKey     *paillier.SecretKey
	ringPedersenSecretKey *intcom.TrapdoorKey

	commitmentKey *hashcom.CommitmentKey

	prmfs           *fiatshamir.Protocol[*prm.Statement, *prm.Witness, *prm.Commitment, *prm.State, *prm.Response]
	additiveSharing *additive.Scheme[S]
	schnorrScheme   *batch_schnorr.Protocol[P, S]

	blummodfs *fiatshamir.Protocol[*blummod.Statement, *blummod.Witness, *blummod.Commitment, *blummod.State, *blummod.Response]
	facfs     map[sharing.ID]*fiatshamir.Protocol[*fac.Statement, *fac.Witness, *fac.Commitment, *fac.State, *fac.Response]

	psi_i            compiler.NIZKPoKProof
	schnorrStatement *batch_schnorr.Statement[P, S]
	schnorrWitness   *batch_schnorr.Witness[S]
	Ai               *batch_schnorr.Commitment[P, S]
	tau              *batch_schnorr.State[S]
	rid              []byte
	comMsg           *CommitmentMessage[P, B, S]
	u_i              hashcom.Witness

	dhPrivateKeys map[sharing.ID]*dhc.ExtendedPrivateKey[S]
	Yi            map[sharing.ID]*dhc.PublicKey[P, B, S]

	sharesOfZero map[sharing.ID]*additive.Share[S]
	Xi           map[sharing.ID]P

	receivedVjs    map[sharing.ID]hashcom.Commitment
	receivedComMsg map[sharing.ID]*CommitmentMessage[P, B, S]
}

func NewParticipant[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, baseShard *mpc.BaseShard[P, S], prng io.Reader) (*Participant[P, B, S], error) {
	if ctx == nil || baseShard == nil || prng == nil {
		return nil, cggmp21.ErrNil.WithMessage("ctx/baseShard/prng is nil")
	}
	if ctx.HolderID() != baseShard.Share().ID() {
		return nil, cggmp21.ErrValidationFailed.WithMessage("sharing id not part of the quorum")
	}
	if !baseShard.MSP().Shareholders().Equal(ctx.Quorum()) {
		return nil, cggmp21.ErrValidationFailed.WithMessage("quorum does not match base shard's shareholders")
	}
	ctx.Transcript().AppendDomainSeparator(domainSeparator)

	curve, err := algebra.StructureAs[ecdsa.Curve[P, B, S]](baseShard.PublicKeyValue().Structure())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("base shard public key value does not have the expected structure")
	}

	prmInteractiveProtocol, err := prm.NewProtocol(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create PRM protocol")
	}
	prmfs, err := fiatshamir.NewCompiler(prmInteractiveProtocol)
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

	schnorrScheme, err := batch_schnorr.NewProtocol(int(baseShard.MSP().D()), curve, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create ZK scheme")
	}

	commitmentKey, err := hashcom.ExtractCommitmentKey(ctx.Transcript(), ckLabel)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not extract commitment key from transcript")
	}

	blummodInteractiveProtocol, err := blummod.NewProtocol(prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create BlumMod protocol")
	}
	blummodfs, err := fiatshamir.NewCompiler(blummodInteractiveProtocol)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Fiat-Shamir compiler for BlumMod protocol")
	}

	proverCtx := ctx.Clone()
	proverCtx.Transcript().AppendBytes(proverIDLabel, ctx.HolderID().Bytes())
	verifierCtxs := make(map[sharing.ID]*session.Context)
	for id := range ctx.OtherPartiesOrdered() {
		verifierCtx := ctx.Clone()
		verifierCtx.Transcript().AppendBytes(proverIDLabel, id.Bytes())
		verifierCtxs[id] = verifierCtx
	}

	return &Participant[P, B, S]{
		ctx:       ctx,
		curve:     curve,
		baseShard: baseShard,
		prng:      prng,
		round:     1,
		state: state[P, B, S]{
			proverCtx:       proverCtx,
			verifierCtxs:    verifierCtxs,
			prmfs:           prmfs,
			additiveSharing: additiveSharing,
			schnorrScheme:   schnorrScheme,
			commitmentKey:   commitmentKey,
			blummodfs:       blummodfs,

			facfs: make(map[sharing.ID]*fiatshamir.Protocol[*fac.Statement, *fac.Witness, *fac.Commitment, *fac.State, *fac.Response], ctx.Quorum().Size()-1),

			dhPrivateKeys: make(map[sharing.ID]*dhc.ExtendedPrivateKey[S], ctx.Quorum().Size()),
			Yi:            make(map[sharing.ID]*dhc.PublicKey[P, B, S], ctx.Quorum().Size()),

			sharesOfZero: make(map[sharing.ID]*additive.Share[S], ctx.Quorum().Size()),
			Xi:           make(map[sharing.ID]P, ctx.Quorum().Size()),

			rid: make([]byte, curve.ElementSize()),

			receivedVjs:    make(map[sharing.ID]hashcom.Commitment, ctx.Quorum().Size()-1),
			receivedComMsg: make(map[sharing.ID]*CommitmentMessage[P, B, S], ctx.Quorum().Size()-1),
		},
	}, nil
}

func (p *Participant[P, B, S]) Kappa() int {
	return p.curve.ElementSize()
}

func (p *Participant[P, B, S]) Ell() int {
	return p.Kappa()
}

func (p *Participant[P, B, S]) Epislon() int {
	return 2 * p.Kappa()
}

// SharingID returns the sharing identifier of the local participant.
func (p *Participant[P, B, S]) SharingID() sharing.ID {
	return p.baseShard.Share().ID()
}
