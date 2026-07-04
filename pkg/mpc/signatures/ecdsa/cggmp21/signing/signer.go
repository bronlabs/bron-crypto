package signing

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/feldman"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/hjky"
	"github.com/bronlabs/bron-crypto/pkg/network"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const (
	protocolDomainSeparator = "BRON_CRYPTO_MPC_ECDSA_CGGMP21-SIGN"

	publicKeyValueLabel = "BRON_CRYPTO_MPC_ECDSA_CGGMP21-SIGN_PK"
	ridLabel            = "BRON_CRYPTO_MPC_ECDSA_CGGMP21-SIGN_RID"
	proverID            = "BRON_CRYPTO_MPC_ECDSA_CGGMP21-SIGN_PROVER-ID"
)

// Signer holds the local state for one CGGMP21 online signing session.
type Signer[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	zeroParty *hjky.Participant[P, S]

	ctx                 *session.Context
	ecdsaSuite          *sigecdsa.Suite[P, B, S]
	params              *cggmp21.Parameters[P, B, S]
	shard               *cggmp21.Shard[P, B, S]
	zeroAccessStructure *unanimity.Unanimity
	sharingScheme       *feldman.Scheme[P, S]
	prng                io.Reader
	state               state[P, B, S]
}

type state[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	round             network.Round
	x                 S
	k                 S
	rho               *paillier.Nonce
	bigKJ             map[sharing.ID]*paillier.Ciphertext
	gamma             S
	nu                *paillier.Nonce
	bigYJ             map[sharing.ID]*indcpacom.HomomorphicCommitmentKey[*elgamal.PublicKey[P, S], *elgamal.Plaintext[P, S], *elgamal.Nonce[S], *elgamal.Ciphertext[P, S], S]
	a                 *indcpacom.Witness[*elgamal.Nonce[S]]
	b                 *indcpacom.Witness[*elgamal.Nonce[S]]
	bigAJ             map[sharing.ID]*indcpacom.Commitment[*elgamal.Ciphertext[P, S]]
	bigBJ             map[sharing.ID]*indcpacom.Commitment[*elgamal.Ciphertext[P, S]]
	betaJ             map[sharing.ID]*num.Int
	betaHatJ          map[sharing.ID]*num.Int
	rJ                map[sharing.ID]*paillier.Nonce
	sJ                map[sharing.ID]*paillier.Nonce
	rHatJ             map[sharing.ID]*paillier.Nonce
	sHatJ             map[sharing.ID]*paillier.Nonce
	bigDSentJ         map[sharing.ID]*paillier.Ciphertext
	bigFSentJ         map[sharing.ID]*paillier.Ciphertext
	bigDHatSentJ      map[sharing.ID]*paillier.Ciphertext
	bigFHatSentJ      map[sharing.ID]*paillier.Ciphertext
	bigDReceivedJ     map[sharing.ID]*paillier.Ciphertext
	bigFReceivedJ     map[sharing.ID]*paillier.Ciphertext
	bigDHatReceivedJ  map[sharing.ID]*paillier.Ciphertext
	bigFHatReceivedJ  map[sharing.ID]*paillier.Ciphertext
	delta             S
	deltaJ            map[sharing.ID]S
	deltaInt          *num.Int
	chi               S
	chiInt            *num.Int
	bigGamma          P
	bigGammaJ         map[sharing.ID]P
	bigDeltaJ         map[sharing.ID]P
	bigSJ             map[sharing.ID]P
	bigDeltaTildeJ    map[sharing.ID]P
	bigSTildeJ        map[sharing.ID]P
	m                 S
	partialPublicKeys map[sharing.ID]P

	round1Broadcasts map[sharing.ID]*Round1Broadcast[P, B, S]
	round2Broadcasts map[sharing.ID]*Round2Broadcast[P, B, S]
	round3Broadcasts map[sharing.ID]*Round3Broadcast[P, B, S]
}

// NewSigner constructs a CGGMP21 online signer for one session participant.
func NewSigner[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](ctx *session.Context, ecdsaSuite *sigecdsa.Suite[P, B, S], shard *cggmp21.Shard[P, B, S], prng io.Reader) (*Signer[P, B, S], error) {
	if ctx == nil {
		return nil, cggmp21.ErrNil.WithMessage("session context")
	}
	if ecdsaSuite == nil {
		return nil, cggmp21.ErrNil.WithMessage("ECDSA suite")
	}
	if shard == nil {
		return nil, cggmp21.ErrNil.WithMessage("shard")
	}
	if prng == nil {
		return nil, cggmp21.ErrNil.WithMessage("prng")
	}

	ctx.Transcript().AppendDomainSeparator(protocolDomainSeparator)
	unanimityAccessStructure, err := unanimity.NewUnanimityAccessStructure(ctx.Quorum())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create minimal qualified access structure")
	}
	zeroParty, err := hjky.NewParticipant(ctx, unanimityAccessStructure, ecdsaSuite.Curve(), prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create zero participant")
	}
	scheme, err := kw.NewInducedScheme(shard.MSP())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create induced sharing scheme")
	}
	sharingScheme, err := feldman.NewSchemeFromKW(ecdsaSuite.Curve(), scheme)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Feldman sharing scheme")
	}
	xShare, err := sharingScheme.ConvertShareToAdditive(shard.Share(), unanimityAccessStructure)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert share to additive share")
	}
	logN := shard.AuxInfo().PaillierSecretKey().PlaintextGroup().Modulus().TrueLen()
	params, err := cggmp21.NewParameters(ecdsaSuite.Curve(), logN)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create CGGMP21 parameters")
	}

	signer := &Signer[P, B, S]{
		zeroParty: zeroParty,

		ctx:                 ctx,
		ecdsaSuite:          ecdsaSuite,
		params:              params,
		shard:               shard,
		zeroAccessStructure: unanimityAccessStructure,
		sharingScheme:       sharingScheme,
		prng:                prng,
		//nolint:exhaustruct // lazy initialisation
		state: state[P, B, S]{
			round: 1,
			x:     xShare.Value(),
		},
	}

	return signer, nil
}

// SharingID returns the signer party identifier.
func (s *Signer[P, B, S]) SharingID() sharing.ID {
	return s.ctx.HolderID()
}

func (s *Signer[P, B, S]) computeEffectivePartialPublicKeys(
	zeroShare *feldman.Share[S],
	zeroVerificationVector *feldman.VerificationVector[P, S],
) (effectivePublicKeys map[sharing.ID]P, offset S, err error) {
	var zero S
	zeroSharingScheme, err := feldman.NewScheme(s.params.CurveGroup(), s.zeroAccessStructure)
	if err != nil {
		return nil, zero, errs.Wrap(err).WithMessage("cannot create zero-sharing Feldman scheme")
	}
	zeroAdditiveShare, err := zeroSharingScheme.ConvertShareToAdditive(zeroShare, s.zeroAccessStructure)
	if err != nil {
		return nil, zero, errs.Wrap(err).WithMessage("cannot convert zero share to additive share")
	}
	zeroLiftedDealerFunc, err := feldman.NewLiftedDealerFunc(zeroVerificationVector, zeroSharingScheme.MSP())
	if err != nil {
		return nil, zero, errs.Wrap(err).WithMessage("cannot create zero-share lifted dealer function")
	}

	out := make(map[sharing.ID]P)
	publicKeyShares := s.shard.PublicKeyShares()
	for id := range s.ctx.AllPartiesOrdered() {
		publicKeyShare, ok := publicKeyShares.Get(id)
		if !ok {
			return nil, zero, cggmp21.ErrValidationFailed.WithMessage("missing public key share for %d", id)
		}
		additivePublicKeyShare, err := s.sharingScheme.ConvertLiftedShareToAdditive(publicKeyShare, s.zeroAccessStructure)
		if err != nil {
			return nil, zero, errs.Wrap(err).WithMessage("cannot convert public key share for %d to additive share", id)
		}
		zeroLiftedShare, err := zeroLiftedDealerFunc.ShareOf(id)
		if err != nil {
			return nil, zero, errs.Wrap(err).WithMessage("cannot compute zero public share for %d", id)
		}
		zeroPublicKeyShare, err := zeroSharingScheme.ConvertLiftedShareToAdditive(zeroLiftedShare, s.zeroAccessStructure)
		if err != nil {
			return nil, zero, errs.Wrap(err).WithMessage("cannot convert zero public share for %d to additive share", id)
		}

		effectivePublicKey := additivePublicKeyShare.Value().Add(zeroPublicKeyShare.Value())
		if effectivePublicKey.IsZero() {
			return nil, zero, base.ErrAbort.WithMessage("effective partial public key for shareholder %d is the identity element after zero-shift; zero sharing must be retried", id)
		}
		out[id] = effectivePublicKey
	}
	return out, zeroAdditiveShare.Value(), nil
}
