package bigint

import (
	"math/big"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl"
)

// ImplAdapter allows the input and output types to be NatPlus, Nat, Int etc as needed.
type Arithmetic[T impl.ImplAdapter[T, *BigInt]] struct {
	impl.ArithmeticMixin[T]
	wrap    func(x *BigInt) (T, error)
	modulus *BigInt
}

func (a *Arithmetic[T]) New(v uint64) T {
	out, err := a.wrap(New(new(big.Int).SetUint64(v)))
	if err != nil {
		panic(err)
	}
	return out
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
	return a.wrap(x.Impl().Neg())
}

func (a *Arithmetic[T]) Sqrt(x T) (T, error) {
	if err := a.ValidateSqrt(x); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	return a.wrap(x.Impl().Sqrt())
}

func (a *Arithmetic[T]) Add(x, y T, _ int) (T, error) {
	if err := a.ValidateAdd(x, y); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	return a.wrap(x.Impl().Add(y.Impl()))
}

func (a *Arithmetic[T]) Sub(x, y T, _ int) (T, error) {
	if err := a.ValidateSub(x, y); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	return a.wrap(x.Impl().Sub(y.Impl()))
}

func (a *Arithmetic[T]) Mul(x, y T, _ int) (T, error) {
	if err := a.ValidateMul(x, y); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	return a.wrap(x.Impl().Mul(y.Impl()))
}

func (a *Arithmetic[T]) Div(x, y T, _ int) (quot, rem T, err error) {
	if err := a.ValidateDiv(x, y); err != nil {
		return *new(T), *new(T), errs.WrapValidation(err, "invalid argument")
	}
	q, r, err := x.Impl().Div(y.Impl())
	if err != nil {
		return *new(T), *new(T), errs.WrapFailed(err, "could not do euclidean division")
	}
	quot, err = a.wrap(q)
	if err != nil {
		return *new(T), *new(T), errs.WrapFailed(err, "could not wrap quotient")
	}
	rem, err = a.wrap(r)
	if err != nil {
		return *new(T), *new(T), errs.WrapFailed(err, "could not wrap remainder")
	}
	return quot, rem, nil
}

func (a *Arithmetic[T]) Mod(x, m T) (T, error) {
	if err := a.ValidateMod(x, m); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	out, err := x.Impl().Mod(m.Impl())
	if err != nil {
		return *new(T), errs.WrapFailed(err, "coudl not compute x mod m")
	}
	return a.wrap(out)
}

func (a *Arithmetic[T]) Exp(x, y T) (T, error) {
	if err := a.ValidateExp(x, y); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	return a.wrap(x.Impl().Exp(y.Impl(), a.modulus))
}

func (a *Arithmetic[T]) SimExp(bases, exponents []T) (T, error) {
	if err := a.ValidateSimExp(bases, exponents); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}

	out := bases[0].Impl().Exp(exponents[0].Impl(), a.modulus)
	for i, bi := range bases {
		out = out.Mul(bi.Impl().Exp(exponents[i].Impl(), a.modulus))
	}
	return a.wrap(out)
}

func (a *Arithmetic[T]) MultiBaseExp(bases []T, exponent T) (T, error) {
	if err := a.ValidateMultiBaseExp(bases, exponent); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}

	out := bases[0].Impl().Exp(exponent.Impl(), a.modulus)
	for _, b := range bases[1:] {
		out = out.Mul(b.Impl().Exp(exponent.Impl(), a.modulus))
	}
	return a.wrap(out)
}

func (a *Arithmetic[T]) MultiExponentExp(b T, exponents []T) (T, error) {
	if err := a.ValidateMultiExponentExp(b, exponents); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}

	e := exponents[0].Impl()
	for _, ei := range exponents {
		e = e.Add(ei.Impl())
	}
	return a.wrap(b.Impl().Exp(e, a.modulus))
}

type ModularArithmetic[T impl.ImplAdapter[T, *BigInt]] struct {
	Arithmetic[T]
}

func (a *ModularArithmetic[T]) Inverse(x T) (T, error) {
	if err := a.ValidateInverse(x); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	out, err := x.Impl().ModInverse(a.modulus)
	if err != nil {
		return *new(T), errs.WrapFailed(err, "could not take modular inverse")
	}
	return a.wrap(out)
}

func (a *ModularArithmetic[T]) QuadraticResidue(x T) (T, error) {
	if err := a.ValidateQuadraticResidue(x); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}

	out, err := x.Impl().ModSqrt(a.modulus)
	if err != nil {
		return *new(T), errs.WrapFailed(err, "could not compute quadratic residue")
	}
	if out.V == nil {
		return *new(T), errs.NewValue("element has no quadratic residue")
	}
	return a.wrap(out)
}

func (a *ModularArithmetic[T]) Modulus() T {
	out, err := a.wrap(a.modulus)
	if err != nil {
		panic(err)
	}
	return out
}

func NewSignedArithmetic[T impl.ImplAdapter[T, *BigInt]](size int, wrap func(*BigInt) (T, error), validate bool) *Arithmetic[T] {
	out := &Arithmetic[T]{
		ArithmeticMixin: impl.ArithmeticMixin[T]{
			Ctx: &impl.ArithmeticContext{
				Size:           size,
				ValidateInputs: validate,
			},
		},
		wrap: wrap,
	}
	out.ArithmeticMixin.H = out
	return out
}

func NewUnsignedPositiveArithmetic[T impl.ImplAdapter[T, *BigInt]](size int, wrap func(*BigInt) (T, error), validate bool) *Arithmetic[T] {
	out := &Arithmetic[T]{
		ArithmeticMixin: impl.ArithmeticMixin[T]{
			Ctx: &impl.ArithmeticContext{
				BottomAtOne:    true,
				Size:           size,
				ValidateInputs: validate,
			},
		},
		wrap: wrap,
	}
	out.ArithmeticMixin.H = out
	return out
}

func NewUnsignedArithmetic[T impl.ImplAdapter[T, *BigInt]](size int, wrap func(*BigInt) (T, error), validate bool) *Arithmetic[T] {
	out := &Arithmetic[T]{
		ArithmeticMixin: impl.ArithmeticMixin[T]{
			Ctx: &impl.ArithmeticContext{
				BottomAtZero:   true,
				Size:           size,
				ValidateInputs: validate,
			},
		},
		wrap: wrap,
	}
	out.ArithmeticMixin.H = out
	return out
}

func NewModularArithmetic[T impl.ImplAdapter[T, *BigInt], M impl.ImplAdapter[M, *BigInt]](modulus M, wrap func(*BigInt) (T, error), validate bool) (*ModularArithmetic[T], error) {
	m := modulus.Impl()
	if m == nil {
		return nil, (errs.NewIsNil("modulus"))
	}
	if m.Equal(Zero) {
		return nil, (errs.NewValue("modulus is zero"))
	}
	out := &ModularArithmetic[T]{
		Arithmetic: Arithmetic[T]{
			ArithmeticMixin: impl.ArithmeticMixin[T]{
				Ctx: &impl.ArithmeticContext{
					BottomAtZero:   true,
					Modular:        true,
					Size:           -1,
					ValidateInputs: validate,
				},
			},
			modulus: m,
			wrap:    wrap,
		},
	}
	out.ArithmeticMixin.H = out
	return out, nil
}
