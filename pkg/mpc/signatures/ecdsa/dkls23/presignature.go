package dkls23

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

// PreSignature holds secret message-independent DKLs23 signing material.
// It must be finalised at most once. Reuse leaks the signing key share.
type PreSignature[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	bigR P
	rx   S
	u    S
	v    S
	phi  S
}

// MarshalCBOR encodes the presignature in CBOR.
func (p *PreSignature[P, B, S]) MarshalCBOR() ([]byte, error) {
	dto := &preSignatureDTO[P, B, S]{
		R:   p.bigR,
		RX:  p.rx,
		U:   p.u,
		V:   p.v,
		Phi: p.phi,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal dkls23 PreSignature")
	}
	return data, nil
}

// UnmarshalCBOR decodes the presignature from CBOR.
func (p *PreSignature[P, B, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*preSignatureDTO[P, B, S]](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal dkls23 PreSignature")
	}
	p2, err := NewPreSignature(dto.R, dto.RX, dto.U, dto.V, dto.Phi)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to create dkls23 PreSignature")
	}

	*p = *p2
	return nil
}

type preSignatureDTO[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	R   P `cbor:"r"`
	RX  S `cbor:"rx"`
	U   S `cbor:"u"`
	V   S `cbor:"v"`
	Phi S `cbor:"phi"`
}

// NewPreSignature returns a new presignature.
func NewPreSignature[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](bigR P, rx, u, v, phi S) (*PreSignature[P, B, S], error) {
	if utils.IsNil(bigR) || utils.IsNil(rx) || utils.IsNil(u) || utils.IsNil(v) || utils.IsNil(phi) || bigR.IsOpIdentity() {
		return nil, ErrFailed.WithMessage("invalid arguments")
	}

	return &PreSignature[P, B, S]{
		bigR: bigR,
		rx:   rx,
		u:    u,
		v:    v,
		phi:  phi,
	}, nil
}

// Finalise completes the partial signature over message.
func (p *PreSignature[P, B, S]) Finalise(suite *sigecdsa.Suite[P, B, S], message []byte) (*PartialSignature[P, B, S], error) {
	if suite == nil {
		return nil, ErrNil.WithMessage("suite")
	}
	digest, err := hashing.Hash(suite.HashFunc(), message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot hash message")
	}
	m, err := sigecdsa.DigestToScalar(suite.ScalarField(), digest)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute message scalar")
	}
	w := m.Mul(p.phi).Add(p.rx.Mul(p.v))

	partialSignature, err := NewPartialSignature(p.bigR, p.u, w)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create partial signature")
	}
	return partialSignature, nil
}
