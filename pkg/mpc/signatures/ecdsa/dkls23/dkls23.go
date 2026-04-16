package dkls23

import (
	crand "crypto/rand"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

// Shard holds a tECDSA key share.
type Shard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	mpc.BaseShard[P, S]
}

// PublicKey returns the public key.
func (sh *Shard[P, B, S]) PublicKey() *sigecdsa.PublicKey[P, B, S] {
	pkValue := sh.PublicKeyValue()
	pk, err := sigecdsa.NewPublicKey(pkValue)
	if err != nil {
		panic(err) // this should never happen.
	}
	return pk
}

func (sh *Shard[P, B, S]) Equal(rhs *Shard[P, B, S]) bool {
	return sh.BaseShard.Equal(&rhs.BaseShard)
}

// NewShard returns a new shard.
func NewShard[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](baseShard *mpc.BaseShard[P, S]) (*Shard[P, B, S], error) {
	if baseShard == nil {
		return nil, ErrNil.WithMessage("base shard")
	}

	return &Shard[P, B, S]{BaseShard: *baseShard}, nil
}

type PartialSignature[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	r P
	u S
	w S
}

// MarshalCBOR encodes the partial signature in CBOR.
func (ps *PartialSignature[P, B, S]) MarshalCBOR() ([]byte, error) {
	dto := &partialSignatureDTO[P, B, S]{
		R: ps.r,
		U: ps.u,
		W: ps.w,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal dkls23 PartialSignature")
	}
	return data, nil
}

// UnmarshalCBOR decodes the partial signature from CBOR.
func (ps *PartialSignature[P, B, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*partialSignatureDTO[P, B, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal dkls23 PartialSignature")
	}
	ps2, err := NewPartialSignature(dto.R, dto.U, dto.W)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create dkls23 PartialSignature")
	}

	*ps = *ps2
	return nil
}

type partialSignatureDTO[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	R P `cbor:"r"`
	U S `cbor:"u"`
	W S `cbor:"w"`
}

// NewPartialSignature returns a new partial signature.
func NewPartialSignature[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](r P, u, w S) (*PartialSignature[P, B, S], error) {
	if utils.IsNil(r) || utils.IsNil(u) || utils.IsNil(w) || r.IsOpIdentity() || w.IsZero() || u.IsZero() {
		return nil, ErrFailed.WithMessage("invalid arguments")
	}

	ps := &PartialSignature[P, B, S]{
		r,
		u,
		w,
	}
	return ps, nil
}

// Aggregate computes the sum of partial signatures to get a valid signature. It also normalises the signature to the low-s form as well as attaches the recovery id to the final signature.
func Aggregate[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](suite *sigecdsa.Suite[P, B, S], publicKey *sigecdsa.PublicKey[P, B, S], message []byte, partialSignatures ...*PartialSignature[P, B, S]) (*sigecdsa.Signature[S], error) {
	if len(partialSignatures) == 0 {
		return nil, ErrFailed.WithMessage("no partial signatures provided")
	}
	w := suite.ScalarField().Zero()
	u := suite.ScalarField().Zero()

	r := partialSignatures[0].r
	for i, partialSignature := range partialSignatures {
		w = w.Add(partialSignature.w)
		u = u.Add(partialSignature.u)

		if !partialSignature.r.Equal(r) {
			return nil, base.ErrAbort.WithMessage("partial signature mismatch between indices 0 and %d", i)
		}
	}

	uInv, err := u.TryInv()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute w/u")
	}
	s := w.Mul(uInv)

	rxi, err := r.AffineX()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute affine x")
	}
	rx, err := suite.ScalarField().FromWideBytes(rxi.Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert to scalar")
	}

	v, err := sigecdsa.ComputeRecoveryID(r)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not compute recovery id")
	}

	signature, err := sigecdsa.NewSignature(rx, s, &v)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create signature")
	}
	signature.Normalise()

	scheme, err := sigecdsa.NewScheme(suite, crand.Reader)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create scheme")
	}
	verifier, err := scheme.Verifier()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create verifier")
	}
	if err := verifier.Verify(signature, publicKey, message); err != nil {
		return nil, errs.Join(base.ErrAbort, errs.Wrap(err)).WithMessage("signature is invalid")
	}

	return signature, nil
}
