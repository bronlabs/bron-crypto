package bigint

import (
	"math/big"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	aimpl "github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl"
)

var _ integer.Arithmetic[*NatPlus] = (*Arithmetic[*NatPlus])(nil)

type Arithmetic[T aimpl.ImplAdapter[T, *BigInt]] struct {
	impl.ArithmeticMixin[T, *BigInt]
}

func (*Arithmetic[T]) wrap(x *BigInt) T {
	var t T
	return t.New(x)
}

func (a *Arithmetic[T]) New(v uint64) T {
	return a.wrap(New(new(big.Int).SetUint64(v)))
}

func (a *Arithmetic[T]) Uint64(x T) uint64 {
	return x.Impl().Uint64()
}

func (*Arithmetic[T]) Cmp(x, y T) algebra.Ordering {
	return x.Impl().Cmp(y.Impl())
}

func (*Arithmetic[T]) IsEven(x T) bool {
	return x.Impl().IsEven()
}

func (*Arithmetic[T]) IsProbablyPrime(x T) bool {
	return x.Impl().IsProbablyPrime()
}

func (a *Arithmetic[T]) Neg(x T) (T, error) {
	if err := a.ValidateNeg(x); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	return a.wrap(x.Impl().Neg()), nil
}

func (a *Arithmetic[T]) Sqrt(x T) (T, error) {
	if err := a.ValidateSqrt(x); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	return a.wrap(x.Impl().Sqrt()), nil
}

func (a *Arithmetic[T]) Add(x, y T) (T, error) {
	if err := a.ValidateAdd(x, y); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	return a.wrap(x.Impl().Add(y.Impl())), nil
}

func (a *Arithmetic[T]) Sub(x, y T) (T, error) {
	if err := a.ValidateSub(x, y); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	return a.wrap(x.Impl().Sub(y.Impl())), nil
}

func (a *Arithmetic[T]) Mul(x, y T) (T, error) {
	if err := a.ValidateMul(x, y); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	return a.wrap(x.Impl().Mul(y.Impl())), nil
}

func (a *Arithmetic[T]) Div(x, y T) (quot, rem T, err error) {
	if err := a.ValidateDiv(x, y); err != nil {
		return *new(T), *new(T), errs.WrapValidation(err, "invalid argument")
	}
	q, r, err := x.Impl().Div(y.Impl())
	if err != nil {
		return *new(T), *new(T), errs.WrapFailed(err, "could not do euclidean division")
	}
	return a.wrap(q), a.wrap(r), nil
}

func (a *Arithmetic[T]) Mod(x, m T) (T, error) {
	if err := a.ValidateMod(x, m); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	out, err := x.Impl().Mod(m.Impl())
	if err != nil {
		return *new(T), errs.WrapFailed(err, "coudl not compute x mod m")
	}
	return a.wrap(out), nil
}

func (a *Arithmetic[T]) Exp(x, y T) (T, error) {
	if err := a.ValidateExp(x, y); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	return a.wrap(x.Impl().Exp(y.Impl())), nil
}

func (a *Arithmetic[T]) SimExp(bases, exponents []T) (T, error) {
	if err := a.ValidateSimExp(bases, exponents); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	out := bases[0].Impl().Exp(exponents[0].Impl())
	for i, bi := range bases {
		out = out.Mul(bi.Impl().Exp(exponents[i].Impl()))
	}
	return a.wrap(out), nil
}

func (a *Arithmetic[T]) MultiBaseExp(bases []T, exponent T) (T, error) {
	if err := a.ValidateMultiBaseExp(bases, exponent); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	out := bases[0].Impl().Exp(exponent.Impl())
	for _, b := range bases[1:] {
		out = out.Mul(b.Impl().Exp(exponent.Impl()))
	}
	return a.wrap(out), nil
}

func (a *Arithmetic[T]) MultiExponentExp(b T, exponents []T) (T, error) {
	if err := a.ValidateMultiExponentExp(b, exponents); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	e := exponents[0].Impl()
	for _, ei := range exponents {
		e = e.Add(ei.Impl())
	}
	return a.wrap(b.Impl().Exp(e)), nil
}

type SignedArithmetic[T aimpl.ImplAdapter[T, *BigInt]] struct {
	Arithmetic[T]
}

func (sa *SignedArithmetic[T]) NewSignedArithmetic(validate bool) *SignedArithmetic[T] {
	return NewSignedArithmetic[T](-1, validate)
}

type UnsignedPositiveArithmetic[T aimpl.ImplAdapter[T, *BigInt]] struct {
	Arithmetic[T]
}

func (up *UnsignedPositiveArithmetic[T]) NewUnsignedPositiveArithmetic(validate bool) *UnsignedPositiveArithmetic[T] {
	return NewUnsignedPositiveArithmetic[T](-1, validate)
}

type UnsignedArithmetic[T aimpl.ImplAdapter[T, *BigInt]] struct {
	Arithmetic[T]
}

func (u *UnsignedArithmetic[T]) NewUnsignedArithmetic(validate bool) *UnsignedArithmetic[T] {
	return NewUnsignedArithmetic[T](-1, validate)
}

type ModularArithmetic[T aimpl.ImplAdapter[T, *BigInt]] struct {
	Arithmetic[T]
	modulus T
}

// func (ma *ModularArithmetic[T]) NewModularArithmetic(modulus T, validate bool) *ModularArithmetic[T] {
// 	return NewUnsignedArithmetic[T](-1, validate)
// }

// func (ma *ModularArithmetic[T]) NewPrimesPowerModularArithmetic(primes []T, powers []uint, validate bool) *ModularArithmetic[T] {
// 	return NewUnsignedArithmetic[T](-1, validate)
// }

func NewSignedArithmetic[T aimpl.ImplAdapter[T, *BigInt]](size int, validate bool) *SignedArithmetic[T] {
	out := &SignedArithmetic[T]{
		Arithmetic: Arithmetic[T]{
			ArithmeticMixin: impl.ArithmeticMixin[T, *BigInt]{
				Ctx: &impl.ArithmeticContext{
					Size:           size,
					ValidateInputs: validate,
				},
			},
		},
	}
	out.Arithmetic.ArithmeticMixin.H = out
	return out
}

func NewUnsignedPositiveArithmetic[T aimpl.ImplAdapter[T, *BigInt]](size int, validate bool) *UnsignedPositiveArithmetic[T] {
	out := &UnsignedPositiveArithmetic[T]{
		Arithmetic: Arithmetic[T]{
			ArithmeticMixin: impl.ArithmeticMixin[T, *BigInt]{
				Ctx: &impl.ArithmeticContext{
					BottomAtOne:    true,
					Size:           size,
					ValidateInputs: validate,
				},
			},
		},
	}
	out.Arithmetic.ArithmeticMixin.H = out
	return out
}

func NewUnsignedArithmetic[T aimpl.ImplAdapter[T, *BigInt]](size int, validate bool) *UnsignedArithmetic[T] {
	out := &UnsignedArithmetic[T]{
		Arithmetic: Arithmetic[T]{
			ArithmeticMixin: impl.ArithmeticMixin[T, *BigInt]{
				Ctx: &impl.ArithmeticContext{
					BottomAtZero:   true,
					Size:           size,
					ValidateInputs: validate,
				},
			},
		},
	}
	out.Arithmetic.ArithmeticMixin.H = out
	return out
}

func NewModularArithmetic[T aimpl.ImplAdapter[T, *BigInt]](modulus T, size int, validate bool) (*ModularArithmetic[T], error) {
	m := modulus.Impl()
	if m == nil {
		return nil, (errs.NewIsNil("modulus"))
	}
	if m.Equal(Zero) {
		return nil, (errs.NewValue("modulus is zero"))
	}
	out := &ModularArithmetic[T]{
		Arithmetic: Arithmetic[T]{
			ArithmeticMixin: impl.ArithmeticMixin[T, *BigInt]{
				Ctx: &impl.ArithmeticContext{
					BottomAtZero:   true,
					Modulus:        m.Nat(),
					Size:           size,
					ValidateInputs: validate,
				},
			},
		},
		modulus: modulus,
	}
	out.ArithmeticMixin.H = out
	return out, nil
}

// func NewNPlusArithmetic[T aimpl.ImplAdapter[T, *BigInt]](size int, validate bool) *BigArithmetic[T] {
// 	out := &BigArithmetic[T]{
// 		ArithmeticMixin: impl.ArithmeticMixin[T, *BigInt]{
// 			Ctx: &impl.ArithmeticContext{
// 				BottomAtOne:    true,
// 				Size:           size,
// 				ValidateInputs: validate,
// 			},
// 		},
// 	}
// 	out.ArithmeticMixin.H = out
// 	return out
// }
