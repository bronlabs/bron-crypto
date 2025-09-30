package polynomials

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/fxamacker/cbor/v2"
)

type ModuleValuedPolynomial[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]] struct {
	coeffs []ME
}

type moduleValuedPolynomialDTO[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]] struct {
	Coeffs []ME `cbor:"coefficients"`
}

func NewModuleValuedPolynomial[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]](coeffs []ME) (*ModuleValuedPolynomial[ME, S], error) {
	if len(coeffs) < 1 {
		return nil, errs.NewFailed("coefficients cannot be < 1")
	}
	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}, nil
}

func (p *ModuleValuedPolynomial[ME, S]) Structure() crtp.Structure[*ModuleValuedPolynomial[ME, S]] {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedPolynomial[ME, S]) Bytes() []byte {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedPolynomial[ME, S]) Clone() *ModuleValuedPolynomial[ME, S] {
	coeffs := make([]ME, len(p.coeffs))
	for i, c := range p.coeffs {
		coeffs[i] = c.Clone()
	}
	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}
}

func (p *ModuleValuedPolynomial[ME, S]) Equal(rhs *ModuleValuedPolynomial[ME, S]) bool {
	for i := 0; i < min(len(p.coeffs), len(rhs.coeffs)); i++ {
		if !p.coeffs[i].Equal(rhs.coeffs[i]) {
			return false
		}
	}
	for i := len(p.coeffs); i < max(len(p.coeffs), len(rhs.coeffs)); i++ {
		if !rhs.coeffs[i].IsOpIdentity() {
			return false
		}
	}
	for i := len(rhs.coeffs); i < max(len(p.coeffs), len(rhs.coeffs)); i++ {
		if !p.coeffs[i].IsOpIdentity() {
			return false
		}
	}

	return true
}

func (p *ModuleValuedPolynomial[ME, S]) HashCode() base.HashCode {
	h := base.HashCode(0)
	for _, c := range p.coeffs {
		h ^= c.HashCode()
	}
	return h
}

func (p *ModuleValuedPolynomial[ME, S]) String() string {
	repr := "["
	for _, c := range p.coeffs {
		repr += fmt.Sprintf("%s, ", c.String())
	}
	repr += "]"
	return repr
}

func (p *ModuleValuedPolynomial[ME, S]) Op(e *ModuleValuedPolynomial[ME, S]) *ModuleValuedPolynomial[ME, S] {
	coeffs := make([]ME, max(len(p.coeffs), len(e.coeffs)))
	for i := 0; i < min(len(p.coeffs), len(e.coeffs)); i++ {
		coeffs[i] = p.coeffs[i].Op(e.coeffs[i])
	}
	for i := len(p.coeffs); i < max(len(p.coeffs), len(e.coeffs)); i++ {
		coeffs[i] = e.coeffs[i].Clone()
	}
	for i := len(e.coeffs); i < max(len(p.coeffs), len(e.coeffs)); i++ {
		coeffs[i] = p.coeffs[i].Clone()
	}

	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}
}

func (p *ModuleValuedPolynomial[ME, S]) IsOpIdentity() bool {
	for _, c := range p.coeffs {
		if !c.IsOpIdentity() {
			return false
		}
	}
	return true
}

func (p *ModuleValuedPolynomial[ME, S]) TryOpInv() (*ModuleValuedPolynomial[ME, S], error) {
	return p.OpInv(), nil
}

func (p *ModuleValuedPolynomial[ME, S]) OpInv() *ModuleValuedPolynomial[ME, S] {
	coeffs := make([]ME, len(p.coeffs))
	for i, c := range p.coeffs {
		coeffs[i] = c.OpInv()
	}

	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}
}

func (p *ModuleValuedPolynomial[ME, S]) ScalarOp(actor S) *ModuleValuedPolynomial[ME, S] {
	coeffs := make([]ME, len(p.coeffs))
	for i := 0; i < len(coeffs); i++ {
		coeffs[i] = p.coeffs[i].ScalarOp(actor)
	}

	return &ModuleValuedPolynomial[ME, S]{
		coeffs: coeffs,
	}
}

func (p *ModuleValuedPolynomial[ME, S]) IsTorsionFree() bool {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedPolynomial[ME, S]) Eval(at S) ME {
	out := p.coeffs[len(p.coeffs)-1].Clone()
	for i := len(p.coeffs) - 2; i >= 0; i-- {
		out = out.ScalarOp(at).Op(p.coeffs[i])
	}
	return out
}

func (p *ModuleValuedPolynomial[ME, S]) MarshalCBOR() ([]byte, error) {
	dto := &moduleValuedPolynomialDTO[ME, S]{
		Coeffs: p.coeffs,
	}
	return cbor.Marshal(dto)
}

func (p *ModuleValuedPolynomial[ME, S]) UnmarshalCBOR(data []byte) error {
	var dto moduleValuedPolynomialDTO[ME, S]
	if err := cbor.Unmarshal(data, &dto); err != nil {
		return err
	}
	p.coeffs = dto.Coeffs
	return nil
}

func LiftPolynomial[ME algebra.ModuleElement[ME, RE], RE algebra.RingElement[RE]](poly *Polynomial[RE], base algebra.ModuleElement[ME, RE]) (*ModuleValuedPolynomial[ME, RE], error) {
	coeffs := make([]ME, len(poly.coeffs))
	for i, c := range poly.coeffs {
		coeffs[i] = base.ScalarOp(c)
	}

	p := &ModuleValuedPolynomial[ME, RE]{
		coeffs: coeffs,
	}
	return p, nil
}
