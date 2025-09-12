package polynomials2

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	"github.com/fxamacker/cbor/v2"
)

type ModuleValuedPolynomial[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]] struct {
	zero   ME
	coeffs []ME
}

type moduleValuedPolynomialDTO[ME algebra.ModuleElement[ME, S], S algebra.RingElement[S]] struct {
	Zero   ME   `cbor:"1"`
	Coeffs []ME `cbor:"2"`
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
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedPolynomial[ME, S]) Equal(rhs *ModuleValuedPolynomial[ME, S]) bool {
	common := min(len(p.coeffs), len(rhs.coeffs))
	for i := 0; i < common; i++ {
		if !p.coeffs[i].Equal(rhs.coeffs[i]) {
			return false
		}
	}
	if len(p.coeffs) > common {
		for i := common; i < len(p.coeffs); i++ {
			if !p.coeffs[i].IsOpIdentity() {
				return false
			}
		}
	}
	if len(rhs.coeffs) > common {
		for i := common; i < len(rhs.coeffs); i++ {
			if !rhs.coeffs[i].IsOpIdentity() {
				return false
			}
		}
	}

	return true
}

func (p *ModuleValuedPolynomial[ME, S]) HashCode() base.HashCode {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedPolynomial[ME, S]) String() string {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedPolynomial[ME, S]) Op(e *ModuleValuedPolynomial[ME, S]) *ModuleValuedPolynomial[ME, S] {
	common := min(len(p.coeffs), len(e.coeffs))
	total := max(len(p.coeffs), len(e.coeffs))
	coeffs := make([]ME, total)
	for i := 0; i < common; i++ {
		coeffs[i] = p.coeffs[i].Op(e.coeffs[i])
	}
	if len(p.coeffs) > common {
		for i := common; i < len(p.coeffs); i++ {
			coeffs[i] = p.coeffs[i]
		}
	}
	if len(e.coeffs) > common {
		for i := common; i < len(e.coeffs); i++ {
			coeffs[i] = e.coeffs[i]
		}
	}

	return &ModuleValuedPolynomial[ME, S]{
		zero:   p.zero,
		coeffs: coeffs,
	}
}

func (p *ModuleValuedPolynomial[ME, S]) IsOpIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedPolynomial[ME, S]) TryOpInv() (*ModuleValuedPolynomial[ME, S], error) {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedPolynomial[ME, S]) OpInv() *ModuleValuedPolynomial[ME, S] {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedPolynomial[ME, S]) ScalarOp(actor S) *ModuleValuedPolynomial[ME, S] {
	coeffs := make([]ME, len(p.coeffs))
	for i := 0; i < len(coeffs); i++ {
		coeffs[i] = p.coeffs[i].ScalarOp(actor)
	}

	return &ModuleValuedPolynomial[ME, S]{
		zero:   p.zero,
		coeffs: coeffs,
	}
}

func (p *ModuleValuedPolynomial[ME, S]) IsTorsionFree() bool {
	//TODO implement me
	panic("implement me")
}

func (p *ModuleValuedPolynomial[ME, S]) Eval(at S) ME {
	if len(p.coeffs) == 0 {
		return p.zero
	}
	out := p.coeffs[len(p.coeffs)-1].Clone()
	for i := len(p.coeffs) - 2; i >= 0; i-- {
		out = out.ScalarOp(at).Op(p.coeffs[i])
	}
	return out
}

func (p *ModuleValuedPolynomial[ME, S]) MarshalCBOR() ([]byte, error) {
	dto := &moduleValuedPolynomialDTO[ME, S]{
		Zero:   p.zero,
		Coeffs: p.coeffs,
	}
	return cbor.Marshal(dto)
}

func (p *ModuleValuedPolynomial[ME, S]) UnmarshalCBOR(data []byte) error {
	var dto moduleValuedPolynomialDTO[ME, S]
	if err := cbor.Unmarshal(data, &dto); err != nil {
		return err
	}
	p.zero = dto.Zero
	p.coeffs = dto.Coeffs
	return nil
}

func LiftPolynomial[ME algebra.ModuleElement[ME, RE], RE algebra.RingElement[RE]](poly *Polynomial[RE], base algebra.ModuleElement[ME, RE]) (*ModuleValuedPolynomial[ME, RE], error) {
	module := algebra.StructureMustBeAs[algebra.Module[ME, RE]](base.Structure())
	zero := module.OpIdentity()
	coeffs := make([]ME, len(poly.coeffs))
	for i, c := range poly.coeffs {
		coeffs[i] = base.ScalarOp(c)
	}

	p := &ModuleValuedPolynomial[ME, RE]{
		zero:   zero,
		coeffs: coeffs,
	}
	return p, nil
}
