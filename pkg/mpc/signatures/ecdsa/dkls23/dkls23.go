package dkls23

import (
	"github.com/bronlabs/errs-go/errs"

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
	dto, err := serde.UnmarshalCBOR[partialSignatureDTO[P, B, S]](data)
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

// R returns the aggregated nonce point the party used; every cosigner's
// partial signature must carry the same one.
func (ps *PartialSignature[P, B, S]) R() P {
	return ps.r
}

// U returns the party's share of r·φ.
func (ps *PartialSignature[P, B, S]) U() S {
	return ps.u
}

// W returns the party's share of φ·(H(m) + r_x·sk).
func (ps *PartialSignature[P, B, S]) W() S {
	return ps.w
}

// NewPartialSignature validates and constructs a signing fragment. It rejects
// zero fragment scalars as degenerate contributions. In the ideal uniform-mask
// model, with a nonzero reduced x-coordinate of the aggregate nonce, each of u
// and w is zero with probability 1/q, about 2^-256 on secp256k1 and P-256.
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
