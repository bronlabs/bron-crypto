package signing

import (
	"encoding/hex"
	"fmt"
	"io"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/lindell17"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/przs"
	schnorrpok "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fischlin"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const (
	transcriptLabel    = "BRON_CRYPTO_LINDELL17_SIGN-"
	commitmentKeyLabel = "BRON_CRYPTO_LINDELL17_SIGN_COMMITMENT_KEY-"
	publicKeyLabel     = "BRON_CRYPTO_LINDELL17_SIGN_PUBLIC_KEY-"
)

// Cosigner holds common state for signing participants.
type Cosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ctx   *session.Context
	round uint
	// Base participant
	prng  io.Reader
	suite *ecdsa.Suite[P, B, S]

	// Threshold participant
	shard                  *lindell17.Shard[P, B, S]
	signingQuorum          *unanimity.Unanimity
	refreshedAdditiveShare S
	zeroShare              S

	commitmentKey *hashcom.CommitmentKey
	niDlogScheme  compiler.NonInteractiveProtocol[*schnorrpok.Statement[P, S], *schnorrpok.Witness[S]]
}

// PrimaryCosignerState tracks the primary cosigner's internal state.
type PrimaryCosignerState[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	k1           S
	bigR1Opening hashcom.Witness
	bigR1Proof   compiler.NIZKPoKProof
	bigR         P
	r            S
	bigR1        P
}

// PrimaryCosigner runs the primary role in Lindell17 signing.
type PrimaryCosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Cosigner[P, B, S]

	secondarySharingID sharing.ID
	state              *PrimaryCosignerState[P, B, S]
}

// SecondaryCosignerState tracks the secondary cosigner's internal state.
type SecondaryCosignerState[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	bigR1Commitment hashcom.Commitment
	k2              S
	bigR2           P
}

// SecondaryCosigner runs the secondary role in Lindell17 signing.
type SecondaryCosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Cosigner[P, B, S]

	primarySharingID sharing.ID
	state            *SecondaryCosignerState[P, B, S]
}

// SharingID returns the cosigner's sharing identifier.
func (cosigner *Cosigner[P, B, S]) SharingID() sharing.ID {
	return cosigner.ctx.HolderID()
}

func newCosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *ecdsa.Suite[P, B, S], hisSharingID sharing.ID, myShard *lindell17.Shard[P, B, S], niCompiler compiler.Name, prng io.Reader, roundNo uint) (cosigner *Cosigner[P, B, S], err error) {
	err = validateInputs(suite, hisSharingID, myShard, niCompiler, ctx, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid input arguments")
	}

	sessionID := ctx.SessionID()
	dst := fmt.Sprintf("%s_%s_%s_%s", transcriptLabel, hex.EncodeToString(sessionID[:]), niCompiler, suite.Curve().Name())
	ctx.Transcript().AppendDomainSeparator(dst)
	ctx.Transcript().AppendBytes(publicKeyLabel, myShard.PublicKeyValue().ToCompressed())

	commitmentKey, err := hashcom.ExtractCommitmentKey(ctx.Transcript(), commitmentKeyLabel)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create commitment key")
	}
	schnorrProtocol, err := schnorrpok.NewProtocol(suite.Curve().Generator(), prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to create schnorr protocol")
	}

	niDlogScheme, err := compiler.Compile(niCompiler, schnorrProtocol, prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to compile niDlogProver")
	}
	kwScheme, err := kw.NewInducedScheme(myShard.MSP())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create signing sharing scheme")
	}
	sharingScheme, err := feldman.NewSchemeFromKW(suite.Curve(), kwScheme)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create signing Feldman scheme")
	}
	zeroShare, err := przs.SampleZeroShare(ctx, suite.ScalarField())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot sample signing zero share")
	}
	signingQuorum, err := unanimity.NewUnanimityAccessStructure(ctx.Quorum())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create signing quorum")
	}
	additiveShare, err := sharingScheme.ConvertShareToAdditive(myShard.Share(), signingQuorum)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert local MSP share to additive")
	}
	return &Cosigner[P, B, S]{
		ctx:                    ctx,
		round:                  roundNo,
		prng:                   prng,
		suite:                  suite,
		shard:                  myShard,
		signingQuorum:          signingQuorum,
		refreshedAdditiveShare: additiveShare.Add(zeroShare).Value(),
		zeroShare:              zeroShare.Value(),
		commitmentKey:          commitmentKey,
		niDlogScheme:           niDlogScheme,
	}, nil
}

// NewPrimaryCosigner constructs a primary cosigner for an authorized two-party
// session. niCompiler must select Fischlin or Randomised Fischlin, and prng
// must be cryptographically secure. Both parties must use the same niCompiler.
func NewPrimaryCosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *ecdsa.Suite[P, B, S], secondarySharingID sharing.ID, myShard *lindell17.Shard[P, B, S], niCompiler compiler.Name, prng io.Reader) (primaryCosigner *PrimaryCosigner[P, B, S], err error) {
	cosigner, err := newCosigner(ctx, suite, secondarySharingID, myShard, niCompiler, prng, 1)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not construct primary cosigner")
	}
	if myShard.PaillierSecretKey() == nil {
		return nil, ErrInvalidArgument.WithMessage("primary shard has no Paillier secret key")
	}
	primaryCosigner = &PrimaryCosigner[P, B, S]{
		Cosigner:           *cosigner,
		secondarySharingID: secondarySharingID,
		//nolint:exhaustruct // partially initialised
		state: &PrimaryCosignerState[P, B, S]{},
	}
	return primaryCosigner, nil
}

// NewSecondaryCosigner constructs a secondary cosigner for an authorized
// two-party session. niCompiler must select Fischlin or Randomised Fischlin,
// and prng must be cryptographically secure. Both parties must use the same
// niCompiler.
func NewSecondaryCosigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, suite *ecdsa.Suite[P, B, S], primarySharingID sharing.ID, myShard *lindell17.Shard[P, B, S], niCompiler compiler.Name, prng io.Reader) (secondaryCosigner *SecondaryCosigner[P, B, S], err error) {
	cosigner, err := newCosigner(ctx, suite, primarySharingID, myShard, niCompiler, prng, 2)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not construct secondary cosigner")
	}
	paillierPublicKeys := myShard.PaillierPublicKeys()
	if paillierPublicKeys == nil {
		return nil, ErrInvalidArgument.WithMessage("secondary shard has no Paillier public keys")
	}
	primaryPaillierPublicKey, exists := paillierPublicKeys.Get(primarySharingID)
	if !exists || primaryPaillierPublicKey == nil {
		return nil, ErrInvalidArgument.WithMessage("secondary shard has no Paillier public key for primary %d", primarySharingID)
	}
	encryptedShares := myShard.EncryptedShares()
	if encryptedShares == nil {
		return nil, ErrInvalidArgument.WithMessage("secondary shard has no encrypted shares")
	}
	primaryEncryptedShares, exists := encryptedShares.Get(primarySharingID)
	if !exists || len(primaryEncryptedShares) == 0 {
		return nil, ErrInvalidArgument.WithMessage("secondary shard has no encrypted share for primary %d", primarySharingID)
	}
	primaryPublicShare, exists := myShard.PublicKeyShares().Get(primarySharingID)
	if !exists || primaryPublicShare == nil {
		return nil, ErrInvalidArgument.WithMessage("secondary shard has no public share for primary %d", primarySharingID)
	}
	if len(primaryEncryptedShares) != len(primaryPublicShare.Value()) {
		return nil, ErrInvalidArgument.WithMessage(
			"primary encrypted share has %d components, expected %d",
			len(primaryEncryptedShares),
			len(primaryPublicShare.Value()),
		)
	}
	for i, encryptedShare := range primaryEncryptedShares {
		if encryptedShare == nil || !primaryPaillierPublicKey.CiphertextGroup().Contains(encryptedShare.Value()) {
			return nil, ErrInvalidArgument.WithMessage("primary encrypted share component %d is invalid", i)
		}
	}

	//nolint:exhaustruct // partially initialised
	secondaryCosigner = &SecondaryCosigner[P, B, S]{
		Cosigner:         *cosigner,
		primarySharingID: primarySharingID,
		state:            &SecondaryCosignerState[P, B, S]{},
	}
	return secondaryCosigner, nil
}

func validateInputs[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](suite *ecdsa.Suite[P, B, S], other sharing.ID, myShard *lindell17.Shard[P, B, S], nic compiler.Name, ctx *session.Context, prng io.Reader) error {
	if suite == nil {
		return ErrInvalidArgument.WithMessage("suite is nil")
	}
	if ctx == nil {
		return ErrInvalidArgument.WithMessage("ctx is nil")
	}
	if prng == nil {
		return ErrInvalidArgument.WithMessage("prng is nil")
	}
	if myShard == nil {
		return ErrInvalidArgument.WithMessage("myShard is nil")
	}
	if myShard.Share() == nil || myShard.MSP() == nil {
		return ErrInvalidArgument.WithMessage("myShard has missing base sharing material")
	}

	if suite.IsDeterministic() {
		return ErrInvalidArgument.WithMessage("suite cannot be deterministic for MPC signing")
	}
	if ctx.Quorum().Size() != lindell17.Threshold {
		return ErrInvalidArgument.WithMessage("Lindell17 signing requires exactly two participants")
	}
	if ctx.HolderID() != myShard.Share().ID() {
		return ErrInvalidArgument.WithMessage("context holder ID %d does not match shard ID %d", ctx.HolderID(), myShard.Share().ID())
	}
	if other == myShard.Share().ID() {
		return ErrInvalidArgument.WithMessage("other sharing ID %d is equal to my sharing ID", other)
	}
	if !ctx.Quorum().Contains(other) || !ctx.Quorum().Contains(myShard.Share().ID()) {
		return ErrInvalidArgument.WithMessage("signing peer IDs do not exactly match the context quorum")
	}
	otherParties := slices.Collect(ctx.OtherPartiesOrdered())
	if len(otherParties) != 1 || otherParties[0] != other {
		return ErrInvalidArgument.WithMessage("context peer %v does not match requested peer %d", otherParties, other)
	}
	if !myShard.MSP().Shareholders().Contains(other) || !myShard.MSP().Shareholders().Contains(myShard.Share().ID()) {
		return ErrInvalidArgument.WithMessage("sharing ID %d not in my shard MSP", other)
	}
	if !myShard.MSP().Accepts(ctx.Quorum().List()...) {
		return ErrInvalidArgument.WithMessage("not authorized quorum")
	}
	if suite.Curve().Name() != myShard.PublicKeyValue().Structure().Name() {
		return ErrInvalidArgument.WithMessage("suite curve does not match shard curve")
	}
	if nic != fischlin.Name && nic != randfischlin.Name {
		return ErrInvalidArgument.WithMessage("Lindell17 signing requires a straight-line extractable compiler")
	}

	return nil
}
