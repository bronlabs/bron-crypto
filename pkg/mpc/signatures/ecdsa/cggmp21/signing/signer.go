package signing

import (
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/hjky"
	"github.com/bronlabs/bron-crypto/pkg/network"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

const (
	protocolDomainSeparator = "BRON_CRYPTO_MPC_ECDSA_CGGMP21-SIGN"
)

type Signer[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	zeroParty *hjky.Participant[P, S]

	ctx         *session.Context
	ecdsaSuite  *sigecdsa.Suite[P, B, S]
	params      *cggmp21.Parameters
	shard       *cggmp21.Shard[P, B, S]
	curveGroup  sigecdsa.Curve[P, B, S]
	scalarField algebra.PrimeField[S]
	prng        io.Reader
	state       state[P, B, S]
}

type state[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	round          network.Round
	x              S
	k              S
	rho            *paillier.Nonce
	gamma          S
	nu             *paillier.Nonce
	bigYJ          map[sharing.ID]*elgamal.PublicKey[P, S]
	a              *elgamal.Nonce[S]
	b              *elgamal.Nonce[S]
	betaJ          map[sharing.ID]*num.Int
	betaHatJ       map[sharing.ID]*num.Int
	delta          S
	chi            S
	bigGamma       P
	bigDeltaJ      map[sharing.ID]P
	bigSJ          map[sharing.ID]P
	bigDeltaTildeJ map[sharing.ID]P
	bigSTildeJ     map[sharing.ID]P
	m              S

	round1Broadcasts map[sharing.ID]*Round1Broadcast[P, B, S]
	round2Broadcasts map[sharing.ID]*Round2Broadcast[P, B, S]
	round3Broadcasts map[sharing.ID]*Round3Broadcast[P, B, S]
}

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
	xShare, err := scheme.ConvertShareToAdditive(shard.Share(), unanimityAccessStructure)
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

		ctx:         ctx,
		ecdsaSuite:  ecdsaSuite,
		params:      params,
		shard:       shard,
		curveGroup:  ecdsaSuite.Curve(),
		scalarField: ecdsaSuite.ScalarField(),
		prng:        prng,
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
