package num

// import (
// 	"fmt"

// 	"github.com/bronlabs/bron-crypto/pkg/base"
// 	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
// 	"github.com/bronlabs/bron-crypto/pkg/ase/nt/cardinal"
// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// 	"github.com/cronokirby/saferith"
// )

// var (
// 	_ algebra.MultiplicativeGroup[*Unit[*Uint]] = (*UnitGroup[*Uint])(nil)
// 	// _ algebra.MultiplicativeGroup[*Unit[*ResidueNumber]] = (*UnitGroup[*ResidueNumber])(nil)

// 	_ algebra.MultiplicativeGroupElement[*Unit[*Uint]] = (*Unit[*Uint])(nil)
// 	// _ algebra.MultiplicativeGroupElement[*Unit[*ResidueNumber]] = (*Unit[*ResidueNumber])(nil)

// 	_ algebra.MultiplicativeModule[*Unit[*Uint], *Int]        = (*UnitGroup[*Uint])(nil)
// 	_ algebra.MultiplicativeModuleElement[*Unit[*Uint], *Int] = (*Unit[*Uint])(nil)
// 	// _ algebra.MultiplicativeModule[*Unit[*ResidueNumber], *Int]        = (*UnitGroup[*ResidueNumber])(nil)
// 	// _ algebra.MultiplicativeModuleElement[*Unit[*ResidueNumber], *Int] = (*Unit[*ResidueNumber])(nil)
// )

// func NewUnitGroup[E algebra.UintLike[E]](zn algebra.ZnLike[E], factors *PrimeFactorisation[E]) (*UnitGroup[E], error) {
// 	if factors == nil {
// 		return nil, fmt.Errorf("factors cannot be nil")
// 	}
// 	order, err := EulerTotient(factors)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to compute order")
// 	}
// 	N := cardinal.NewFromNat(new(saferith.Nat).SetBytes(factors.N().Bytes()))
// 	if zn.Characteristic().Equal(N) {
// 		return nil, errs.WrapFailed(errs.NewFailed("characteristic of Zn does not match the modulus"), "Zn: %s", zn.Name())
// 	}
// 	v := cardinal.NewFromNat(&order.v)
// 	return &UnitGroup[E]{zn: zn, order: v}, nil
// }

// func NewUnitGroupOfUnknownOrder[E algebra.UintLike[E]](zn algebra.ZnLike[E]) (*UnitGroup[E], error) {
// 	if zn == nil {
// 		return nil, errs.NewIsNil("zn")
// 	}
// 	return &UnitGroup[E]{zn: zn, order: cardinal.Unknown}, nil
// }

// type UnitGroup[E algebra.UintLike[E]] struct {
// 	zn    algebra.ZnLike[E]
// 	order cardinal.Cardinal
// }

// func (g *UnitGroup[E]) Name() string {
// 	return fmt.Sprintf("(Z/%sZ)*", g.Modulus().String())
// }

// func (g *UnitGroup[E]) Order() cardinal.Cardinal {
// 	return g.order
// }

// func (g *UnitGroup[E]) OpIdentity() *Unit[E] {
// 	return g.One()
// }

// func (g *UnitGroup[E]) One() *Unit[E] {
// 	return &Unit[E]{v: g.zn.One(), g: g}
// }

// func (g *UnitGroup[E]) Modulus() *NatPlus {
// 	return &NatPlus{v: *g.zn.Characteristic().Value()}
// }

// func (g *UnitGroup[E]) ElementSize() int {
// 	return g.zn.ElementSize()
// }

// func (g *UnitGroup[E]) MultiScalarOp(scs []*Int, ps []*Unit[E]) (*Unit[E], error) {
// 	panic("implement me")
// }

// func (g *UnitGroup[E]) MultiScalarExp(scs []*Int, ps []*Unit[E]) (*Unit[E], error) {
// 	panic("implement me")
// }

// func (g *UnitGroup[E]) FromBytes(input []byte) (*Unit[E], error) {
// 	if len(input) == 0 {
// 		return nil, errs.NewValue("input must not be empty")
// 	}
// 	t, err := Z().FromBytes(input)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to create integer from bytes")
// 	}
// 	if !t.Coprime(g.Modulus().Lift()) {
// 		return nil, errs.NewValue("input is not coprime to modulus")
// 	}
// 	// Let the underlying Zn handle the byte conversion
// 	// It will handle padding/size requirements
// 	v, err := g.zn.FromBytes(input)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to create unit from bytes")
// 	}
// 	return &Unit[E]{v: v, g: g}, nil
// }

// func (g *UnitGroup[E]) FromCardinal(input cardinal.Cardinal) (*Unit[E], error) {
// 	elem, err := g.zn.FromCardinal(input)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to create element from cardinal")
// 	}
// 	t, err := Z().FromCardinal(input)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to create integer from cardinal")
// 	}
// 	if !t.Coprime(g.Modulus().Lift()) {
// 		return nil, errs.NewValue("element is not coprime to modulus")
// 	}
// 	return &Unit[E]{v: elem, g: g}, nil
// }

// func (g *UnitGroup[E]) FromUint64(value uint64) (*Unit[E], error) {
// 	if !Z().FromUint64(value).Coprime(g.Modulus().Lift()) {
// 		return nil, errs.NewValue("value is not coprime to modulus")
// 	}
// 	elem := g.zn.FromUint64(value)
// 	return &Unit[E]{v: elem, g: g}, nil
// }

// func (*UnitGroup[E]) ScalarStructure() algebra.Structure[*Int] {
// 	return Z()
// }

// type Unit[E algebra.UintLike[E]] struct {
// 	v algebra.UintLike[E]
// 	g *UnitGroup[E]
// }

// func (u *Unit[E]) SameModulus(other *Unit[E]) bool {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	return u.g.Modulus().Equal(other.g.Modulus())
// }

// func (u *Unit[E]) Structure() algebra.Structure[*Unit[E]] {
// 	return u.g
// }

// func (u *Unit[E]) Equal(other *Unit[E]) bool {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	otherV, ok := other.v.(E)
// 	if !ok {
// 		panic(errs.NewType("type error"))
// 	}
// 	return u.v.Equal(otherV)
// }

// func (u *Unit[E]) Clone() *Unit[E] {
// 	return &Unit[E]{v: u.v.Clone()}
// }

// func (u *Unit[E]) Op(other *Unit[E]) *Unit[E] {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	return u.Mul(other)
// }

// func (u *Unit[E]) Mul(other *Unit[E]) *Unit[E] {
// 	if !u.SameModulus(other) {
// 		panic(errs.NewFailed("moduli do not match: %s != %s", u.g.Modulus().String(), other.g.Modulus().String()))
// 	}
// 	return &Unit[E]{u.v.Mul(other.v.(E)), u.g}
// }

// func (u *Unit[E]) Exp(other *Unit[E]) *Unit[E] {
// 	if !u.SameModulus(other) {
// 		panic(errs.NewFailed("moduli do not match: %s != %s", u.g.Modulus().String(), other.g.Modulus().String()))
// 	}
// 	panic("exponentiation not implemented for units")
// }

// func (u *Unit[E]) Square() *Unit[E] {
// 	return &Unit[E]{u.v.Square(), u.g}
// }

// func (u *Unit[E]) TryInv() (*Unit[E], error) {
// 	return u.Inv(), nil
// }

// func (u *Unit[E]) Inv() *Unit[E] {
// 	out, err := u.v.TryInv()
// 	if err != nil {
// 		panic(err)
// 	}
// 	return &Unit[E]{out, u.g}
// }

// func (u *Unit[E]) TryOpInv() (*Unit[E], error) {
// 	return u.Inv(), nil
// }

// func (u *Unit[E]) OpInv() *Unit[E] {
// 	return u.Inv()
// }

// func (u *Unit[E]) IsOpIdentity() bool {
// 	return u.IsOne()
// }

// func (u *Unit[E]) IsOne() bool {
// 	return u.v.IsOne()
// }

// func (u *Unit[E]) TryDiv(other *Unit[E]) (*Unit[E], error) {
// 	return u.Div(other), nil
// }

// func (u *Unit[E]) Div(other *Unit[E]) *Unit[E] {
// 	if !u.SameModulus(other) {
// 		panic(errs.NewFailed("moduli do not match: %s != %s", u.g.Modulus().String(), other.g.Modulus().String()))
// 	}
// 	out, err := u.v.TryDiv(other.v.(E))
// 	if err != nil {
// 		panic(err)
// 	}
// 	return &Unit[E]{out, u.g}
// }

// func (u *Unit[E]) HashCode() base.HashCode {
// 	return u.v.HashCode()
// }

// func (u *Unit[E]) ScalarOp(scalar *Int) *Unit[E] {
// 	return u.ScalarExp(scalar)
// }

// func (u *Unit[E]) IsTorsionFree() bool {
// 	panic("implement me")
// }

// func (u *Unit[E]) ScalarExp(sc *Int) *Unit[E] {
// 	panic("implement me")
// }

// func (u *Unit[E]) Cardinal() cardinal.Cardinal {
// 	return u.v.Cardinal()
// }

// func (u *Unit[E]) Bytes() []byte {
// 	return u.v.Bytes()
// }

// func (u *Unit[E]) String() string {
// 	if u == nil {
// 		return "nil"
// 	}
// 	if u.g == nil {
// 		return fmt.Sprintf("Unit<nil>(%s)", u.v.String())
// 	}
// 	return fmt.Sprintf("Unit<%s>(%s)", u.g.Name(), u.v.String())
// }

// type PlainUnit = *Unit[*Uint]

// // type FactoredUnit = *Unit[*ResidueNumber]
