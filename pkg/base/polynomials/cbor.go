package polynomials

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
)

type moduleValuedPolynomialDTO[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]] struct {
	Coeffs []ME `cbor:"coefficients"`
}

func (p *ModuleValuedPolynomial[ME, S]) MarshalCBOR() ([]byte, error) {
	dto := &moduleValuedPolynomialDTO[ME, S]{
		Coeffs: p.coeffs,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal polynomial")
	}
	return data, nil
}

func (p *ModuleValuedPolynomial[ME, S]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*moduleValuedPolynomialDTO[ME, S]](data)
	if err != nil {
		return err
	}
	if len(dto.Coeffs) == 0 {
		return errs.NewFailed("polynomial must have at least one coefficient")
	}
	p.coeffs = dto.Coeffs
	return nil
}

type polynomialDTO[RE algebra.RingElement[RE]] struct {
	Coeffs []RE `cbor:"coefficients"`
}

func (p *Polynomial[RE]) MarshalCBOR() ([]byte, error) {
	dto := &polynomialDTO[RE]{
		Coeffs: p.coeffs,
	}
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to marshal polynomial")
	}
	return data, nil
}

func (p *Polynomial[RE]) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*polynomialDTO[RE]](data)
	if err != nil {
		return err
	}
	if len(dto.Coeffs) == 0 {
		return errs.NewFailed("polynomial must have at least one coefficient")
	}
	p.coeffs = dto.Coeffs
	return nil
}
