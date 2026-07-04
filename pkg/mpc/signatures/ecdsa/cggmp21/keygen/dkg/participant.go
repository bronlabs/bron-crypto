package dkg

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/blummod"
	"github.com/bronlabs/bron-crypto/pkg/proofs/prm"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const (
	domainSeparator = "BRON_CRYPTO_DKG_CGGMP21-"
	ckLabel         = "BRON_CRYPTO_DKG_CGGMP21_CK-"
	proverIDLabel   = "BRON_CRYPTO_DKG_CGGMP21_PROVER_ID-"
	ridLabel        = "BRON_CRYPTO_DKG_CGGMP21_RID-"
)

// Participant runs one party's side of CGGMP21 auxiliary-information generation
// (Figure 7, with the key-refresh part omitted). Over four rounds it samples
// this party's Paillier and ring-Pedersen keys, proves them well-formed,
// verifies every other party's keys and proofs, and attaches the agreed
// auxiliary information to the supplied base shard. It is single-use, holds
// secret key material in its state, and its round methods are not safe for
// concurrent use.
type Participant[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ctx       *session.Context
	curve     ecdsa.Curve[P, B, S]
	baseShard *mpc.BaseShard[P, S]
	params    *cggmp21.Parameters[P, B, S]
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

	prmfs     *fiatshamir.Protocol[*prm.Statement, *prm.Witness, *prm.Commitment, *prm.State, *prm.Response]
	blummodfs *fiatshamir.Protocol[*blummod.Statement, *blummod.Witness, *blummod.Commitment, *blummod.State, *blummod.Response]

	psiI   compiler.NIZKPoKProof
	rid    []byte
	comMsg *CommitmentMessage[P, B, S]
	uI     hashcom.Witness

	receivedVjs map[sharing.ID]hashcom.Commitment

	receivedPaillierPublicKeys         map[sharing.ID]*paillier.PublicKey
	receivedRingPedersenCommitmentKeys map[sharing.ID]*intcom.CommitmentKey
}

// NewParticipant binds a participant to a session context, the party's existing
// secret-share base shard, and an explicit randomness source. It checks that the
// context's holder identity and quorum match the base shard, derives the
// hash-commitment key from the session transcript (domain-separated per this
// protocol), and instantiates the Fiat-Shamir compilers for the Π_prm and Π_mod
// proofs. The base shard's public key must live over an ECDSA curve. prng must
// be a cryptographically secure source; the Paillier/ring-Pedersen key
// generation in Round1 draws from it.
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

	params, err := cggmp21.NewParameters(curve, base.IFCKeyLength)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create CGGMP21 parameters")
	}

	return &Participant[P, B, S]{
		ctx:       ctx,
		curve:     curve,
		baseShard: baseShard,
		params:    params,
		prng:      prng,
		round:     1,
		state: state[P, B, S]{ //nolint:exhaustruct // state is lazy initialised
			proverCtx:     proverCtx,
			verifierCtxs:  verifierCtxs,
			prmfs:         prmfs,
			commitmentKey: commitmentKey,
			blummodfs:     blummodfs,

			rid: make([]byte, params.Kappa()/8),

			receivedVjs:                        make(map[sharing.ID]hashcom.Commitment, ctx.Quorum().Size()-1),
			receivedPaillierPublicKeys:         make(map[sharing.ID]*paillier.PublicKey, ctx.Quorum().Size()-1),
			receivedRingPedersenCommitmentKeys: make(map[sharing.ID]*intcom.CommitmentKey, ctx.Quorum().Size()-1),
		},
	}, nil
}

// SharingID returns the sharing identifier of the local participant.
func (p *Participant[P, B, S]) SharingID() sharing.ID {
	return p.baseShard.Share().ID()
}
