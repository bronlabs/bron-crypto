package num

// import (
// 	"io"

// 	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
// 	"github.com/bronlabs/bron-crypto/pkg/base/algebra/traits"
// 	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// 	"github.com/cronokirby/saferith"
// )

// var (
// 	_ algebra.ZnLike[*ResidueNumber]   = (*ResidueNumberSystem)(nil)
// 	_ algebra.UintLike[*ResidueNumber] = (*ResidueNumber)(nil)

// 	_ algebra.AdditiveModule[*ResidueNumber, *Int]              = (*ResidueNumberSystem)(nil)
// 	_ algebra.AdditiveModuleElement[*ResidueNumber, *Int]       = (*ResidueNumber)(nil)
// 	_ algebra.MultiplicativeModule[*ResidueNumber, *Int]        = (*ResidueNumberSystem)(nil)
// 	_ algebra.MultiplicativeModuleElement[*ResidueNumber, *Int] = (*ResidueNumber)(nil)
// )

// func NewResidueNumberSystemFromPrimeFactorisation[E algebra.UniqueFactorizationMonoidElement[E]](factors *PrimeFactorisation[E]) (*ResidueNumberSystem, error) {
// 	if factors == nil {
// 		return nil, errs.NewIsNil("factors")
// 	}
// 	out, err := NewResidueNumberSystemFromCoprimeFactors(factors.PrimeFactors().Keys()...)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "failed to create residue number system from prime factors")
// 	}
// 	out.canonicalPrimeFactors = factors.PrimeFactors()
// 	return out, nil
// }

// func NewResidueNumberSystemFromCoprimeFactors(bases ...*NatPlus) (*ResidueNumberSystem, error) {
// 	panic("implement me")
// 	// if len(bases) == 0 {
// 	// 	return nil, errs.NewFailed("no bases provided")
// 	// }
// 	// m := one.Clone()
// 	// zs := make([]*Zn, len(bases))
// 	// for i, bi := range bases {
// 	// 	for j, bj := range bases {
// 	// 		if i == j {
// 	// 			continue
// 	// 		}
// 	// 		if bi.Lift().Coprime(bj.Lift()) {
// 	// 			return nil, errs.NewFailed("bases %d and %d are not coprime", i, j)
// 	// 		}
// 	// 	}
// 	// 	m = new(saferith.Nat).Mul(m, &bi.v, -1)
// 	// 	zs[i] = &Zn{n: *bi.Clone()}

// 	// }
// 	// out := &ResidueNumberSystem{m: saferith.ModulusFromNat(m)}
// 	// out.Set(zs...)
// 	// return out, nil
// }

// type ResidueNumberSystem struct {
// 	traits.DirectPowerRing[*Zn, *Uint, *ResidueNumber, ResidueNumber]
// 	m                     *saferith.Modulus
// 	canonicalPrimeFactors ds.Map[*NatPlus, *Nat]
// }

// func (r *ResidueNumberSystem) Name() string {
// 	out := ""
// 	for i, zi := range r.Components() {
// 		out += zi.Name()
// 		if i != len(r.Components())-1 {
// 			out = " X "
// 		}
// 	}
// 	return out
// }

// func (r *ResidueNumberSystem) ElementSize() int {
// 	out := 0
// 	for _, zi := range r.Components() {
// 		out += zi.ElementSize()
// 	}
// 	return out
// }

// func (r *ResidueNumberSystem) WideElementSize() int {
// 	return 2 * r.ElementSize()
// }

// func (r *ResidueNumberSystem) Characteristic() algebra.Cardinal {
// 	return algebra.NewCardinalFromNat(r.m.Nat())
// }

// func (r *ResidueNumberSystem) FromInt(input *Int) (*ResidueNumber, error) {
// 	if input == nil {
// 		return nil, errs.NewIsNil("input")
// 	}
// 	components := make([]*Uint, len(r.Components()))
// 	var err error
// 	for i, zi := range r.Components() {
// 		components[i], err = zi.FromInt(input)
// 		if err != nil {
// 			return nil, errs.WrapFailed(err, "failed to lift input to component %d", i)
// 		}
// 	}
// 	out := &ResidueNumber{}
// 	if err := out.Set(components...); err != nil {
// 		return nil, errs.WrapFailed(err, "failed to set components")
// 	}
// 	return out, nil
// }

// func (r *ResidueNumberSystem) FromUint(input *Uint) (*ResidueNumber, error) {
// 	if input == nil {
// 		return nil, errs.NewIsNil("input")
// 	}
// 	if r.m.Nat().Eq(input.m.Nat()) != 1 {
// 		return nil, errs.NewFailed("input modulus %s does not match system modulus %s", input.Modulus(), r.m)
// 	}
// 	return r.FromInt(input.Lift())
// }

// func (r *ResidueNumberSystem) FromNat(input *Nat) (*ResidueNumber, error) {
// 	if input == nil {
// 		return nil, errs.NewIsNil("input")
// 	}
// 	return r.FromInt(input.Lift())
// }

// func (r *ResidueNumberSystem) FromSafeNat(input *saferith.Nat) (*ResidueNumber, error) {
// 	return r.FromNat(&Nat{v: *input})
// }

// func (r *ResidueNumberSystem) Random(prng io.Reader) (*ResidueNumber, error) {
// 	panic("implement me")
// }

// func (r *ResidueNumberSystem) Hash(bytes []byte) (*ResidueNumber, error) {
// 	panic("implement me")
// }

// type ResidueNumber struct {
// 	traits.DirectPowerRingElement[*Uint, *ResidueNumber, ResidueNumber]
// 	ms []*saferith.Modulus
// 	m  *saferith.Modulus
// 	es []*saferith.Nat
// }

// // Uses 4.5 (Effective Chinese remainder theorem) of Shoup's book
// func (n *ResidueNumber) Canonical() *Uint {
// 	out := zero.Clone()
// 	for i, a := range n.Components() {
// 		aiei := new(saferith.Nat).Mul(&a.v, n.es[i], -1)
// 		out = new(saferith.Nat).ModAdd(out, aiei, n.m)
// 	}
// 	return &Uint{v: *out, m: n.m}
// }

// func (n *ResidueNumber) preCompute() {
// 	n.ms = make([]*saferith.Modulus, len(n.Components()))
// 	m := new(saferith.Nat).SetUint64(1)

// 	for i, c := range n.Components() {
// 		n.ms[i] = c.m
// 		m = new(saferith.Nat).Mul(m, n.ms[i].Nat(), -1)
// 	}

// 	n.m = saferith.ModulusFromNat(m)
// 	n.es = make([]*saferith.Nat, len(n.Components()))

// 	for i := range n.Components() {
// 		miStar := new(saferith.Nat).Div(m, n.ms[i], -1)
// 		bi := new(saferith.Nat).Mod(miStar, n.ms[i])
// 		ti := new(saferith.Nat).ModInverse(bi, n.ms[i])
// 		n.es[i] = new(saferith.Nat).Mul(ti, miStar, -1)
// 	}

// }

// func (n *ResidueNumber) Set(components ...*Uint) error {
// 	if err := n.DirectPowerRingElement.Set(components...); err != nil {
// 		return errs.WrapFailed(err, "failed to set components")
// 	}
// 	return nil
// }

// func (n *ResidueNumber) SetAt(i int, c *Uint) error {
// 	if err := n.DirectPowerRingElement.SetAt(i, c); err != nil {
// 		return errs.WrapFailed(err, "failed to set component at index %d", i)
// 	}
// 	n.preCompute()
// 	return nil
// }

// func (n *ResidueNumber) IsLessThanOrEqual(other *ResidueNumber) bool {
// 	if n.Equal(other) {
// 		return true
// 	}
// 	return n.Canonical().IsLessThanOrEqual(other.Canonical())
// }

// func (n *ResidueNumber) Structure() algebra.Structure[*ResidueNumber] {
// 	zs := make([]*Zn, n.Dimension())
// 	for i, ci := range n.Components() {
// 		zs[i] = &Zn{n: *ci.Modulus()}
// 	}
// 	out := &ResidueNumberSystem{m: n.m}
// 	out.Set(zs...)
// 	return out
// }

// func (n *ResidueNumber) SameModuli(other *ResidueNumber) bool {
// 	if other == nil {
// 		panic("argument is nil")
// 	}
// 	if n.Dimension() != other.Dimension() {
// 		return false
// 	}
// 	for i, c := range n.Components() {
// 		if c.m.Nat().Eq(other.Components()[i].m.Nat()) != 1 {
// 			return false
// 		}
// 	}
// 	return true
// }

// func (n *ResidueNumber) Exp(exponent *ResidueNumber) *ResidueNumber {
// 	if !n.SameModuli(exponent) {
// 		panic("exponent has different moduli")
// 	}
// 	out := &ResidueNumber{}
// 	exponents := exponent.Components()
// 	for i, base := range n.Components() {
// 		out.SetAt(i, base.Exp(exponents[i]))
// 	}
// 	return out
// }

// func (n *ResidueNumber) Clone() *ResidueNumber {
// 	out := &ResidueNumber{}
// 	for i, c := range n.Components() {
// 		out.SetAt(i, c.Clone())
// 	}
// 	return out
// }

// func (n *ResidueNumber) ScalarOp(other *Int) *ResidueNumber {
// 	panic("implement me")
// }

// func (n *ResidueNumber) IsTorsionFree() bool {
// 	panic("implement me")
// }

// func (n *ResidueNumber) ScalarMul(other *Int) *ResidueNumber {
// 	panic("implement me")
// }

// func (n *ResidueNumber) ScalarExp(other *Int) *ResidueNumber {
// 	panic("implement me")
// }

// func (n *ResidueNumber) IsProbablyPrime() bool {
// 	return n.Canonical().IsProbablyPrime()
// }

// func (n *ResidueNumber) SafeNat() *saferith.Nat {
// 	return n.Canonical().SafeNat()
// }

// func (n *ResidueNumber) EuclideanDiv(other *ResidueNumber) (quot, rem *ResidueNumber, err error) {
// 	panic("implement me")
// }

// func (n *ResidueNumber) MarshalBinary() ([]byte, error) {
// 	panic("implement me")
// }

// func (n *ResidueNumber) UnmarshalBinary(data []byte) error {
// 	panic("implement me")
// }
