package impl

import (
	"math/big"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/cronokirby/saferith"
)

type ImplAdapter[E algebra.Element, Impl any] interface {
	Impl() Impl
}

type HolesArithmeticMixin[T any] interface {
	Cmp(x, y T) algebra.Ordering
	New(v uint64) T
}

type ArithmeticMixin[T any] struct {
	Ctx *ArithmeticContext
	H   HolesArithmeticMixin[T]
}

func (a *ArithmeticMixin[T]) Zero() T {
	return a.H.New(0)
}

func (a *ArithmeticMixin[T]) One() T {
	return a.H.New(1)
}

func (a *ArithmeticMixin[T]) anyZeros(xs ...T) bool {
	for _, x := range xs {
		if a.H.Cmp(x, a.Zero()) == algebra.Equal {
			return true
		}
	}
	return false
}

func (a *ArithmeticMixin[T]) validateInputs(xs ...T) error {
	if !a.Ctx.ValidateInputs {
		return nil
	}
	switch a.Ctx.Type() {
	case UnsignedPositive:
		for _, x := range xs {
			if a.H.Cmp(x, a.One()) == algebra.LessThan {
				return errs.NewValue("N+ element can't be less than 1")
			}
		}
	case Unsigned:
		for _, x := range xs {
			if a.H.Cmp(x, a.Zero()) == algebra.LessThan {
				return errs.NewValue("N element can't be less than 0")
			}
		}
	}
	return nil
}

func (a *ArithmeticMixin[T]) validateDenominator(xs ...T) error {
	if !a.Ctx.ValidateInputs {
		return nil
	}
	switch a.Ctx.Type() {
	case UnsignedPositive, Unsigned:
		for _, x := range xs {
			if a.H.Cmp(x, a.One()) == algebra.LessThan {
				return errs.NewValue("denominator < 1")
			}
		}
	case Signed, Modular:
		if someAreZero := a.anyZeros(xs...); someAreZero {
			return errs.NewValue("can't divide by zero")
		}
	}
	return nil
}

func (a *ArithmeticMixin[T]) validateModulus(xs ...T) error {
	if !a.Ctx.ValidateInputs {
		return nil
	}
	if someAreZero := a.anyZeros(xs...); someAreZero {
		return errs.NewValue("moduli can't be less than 1")
	}
	return nil
}

func (a *ArithmeticMixin[T]) ValidateNeg(x T) error {
	if !a.Ctx.ValidateInputs {
		return nil
	}
	if err := a.validateInputs(x); err != nil {
		return errs.WrapValidation(err, "invalid argument")
	}
	if a.Ctx.Type() == Unsigned && a.H.Cmp(x, a.Zero()) != algebra.Equal {
		return errs.NewValue("can only negate 0 in N")
	}
	return nil
}

func (a *ArithmeticMixin[T]) ValidateInverse(x T) error {
	return a.validateDenominator(x)
}

func (a *ArithmeticMixin[T]) ValidateQuadraticResidue(x T) error {
	return a.validateDenominator(x)
}

func (a *ArithmeticMixin[T]) ValidateAdd(x, y T) error {
	return a.validateInputs(x, y)
}

func (a *ArithmeticMixin[T]) ValidateSub(x, y T) error {
	if !a.Ctx.ValidateInputs {
		return nil
	}
	switch a.Ctx.Type() {
	case UnsignedPositive:
		if a.H.Cmp(x, y) == algebra.LessThan {
			return errs.NewValue("x < y")
		}
		if a.H.Cmp(x, a.One()) == algebra.LessThan {
			return errs.NewValue("y < 1")
		}
	case Unsigned:
		if a.H.Cmp(x, y) == algebra.LessThan {
			return errs.NewValue("x < y")
		}
		if a.H.Cmp(x, a.Zero()) == algebra.LessThan {
			return errs.NewValue("x < 0")
		}
	}
	return nil
}

func (a *ArithmeticMixin[T]) ValidateMul(x, y T) error {
	return a.validateInputs(x, y)
}

func (a *ArithmeticMixin[T]) ValidateDiv(x, y T) error {
	if err := a.validateInputs(x); err != nil {
		return errs.WrapValidation(err, "invalid numerator")
	}
	if err := a.validateDenominator(x); err != nil {
		return errs.WrapValidation(err, "invalid denominator")
	}
	return nil
}

func (a *ArithmeticMixin[T]) ValidateExp(x, y T) error {
	return a.validateInputs(x, y)
}

func (a *ArithmeticMixin[T]) ValidateSimExp(bases []T, exponents []T) error {
	if len(bases) == 0 {
		return errs.NewLength("len(bases) == 0")
	}
	if len(exponents) != len(bases) {
		return errs.NewLength("len(exponents) != len(bases)")
	}

	if err := a.validateInputs(bases...); err != nil {
		return err
	}
	if err := a.validateInputs(exponents...); err != nil {
		return err
	}
	return nil
}

func (a *ArithmeticMixin[T]) ValidateMultiBaseExp(bases []T, exponent T) error {
	if len(bases) == 0 {
		return errs.NewLength("len(bases) == 0")
	}
	if err := a.validateInputs(bases...); err != nil {
		return err
	}
	return a.validateInputs(exponent)
}

func (a *ArithmeticMixin[T]) ValidateMultiExponentExp(base T, exponents []T) error {
	if len(exponents) == 0 {
		return errs.NewLength("len(exponents) == 0")
	}
	if err := a.validateInputs(exponents...); err != nil {
		return err
	}
	return a.validateInputs(base)
}

func (a *ArithmeticMixin[T]) ValidateMod(x, m T) error {
	if err := a.validateInputs(x); err != nil {
		return errs.WrapValidation(err, "invalid numerator")
	}
	if err := a.validateModulus(x); err != nil {
		return errs.WrapValidation(err, "invalid modulus")
	}
	return nil
}

func (a *ArithmeticMixin[T]) ValidateSqrt(x T) error {
	if err := a.validateInputs(x); err != nil {
		return errs.WrapValidation(err, "invalid numerator")
	}
	return nil
}

type ArithmeticType string

const (
	Signed                ArithmeticType = "<SIGNED>"
	UnsignedPositive      ArithmeticType = "<UNSIGNED_POSITIVE>"
	Unsigned              ArithmeticType = "<UNSIGNED>"
	Modular               ArithmeticType = "<MODULAR>"
	invalidArithmeticType ArithmeticType = "<INVALID>"
)

type ArithmeticContext struct {
	BottomAtZero   bool
	BottomAtOne    bool
	Modular        bool
	Size           int
	ValidateInputs bool
}

func (ctx *ArithmeticContext) Type() ArithmeticType {
	if ctx.IsSigned() {
		return Signed
	}
	if ctx.IsUnsignedPositive() {
		return UnsignedPositive
	}
	if ctx.IsUnsigned() {
		return Unsigned
	}
	if ctx.IsModular() {
		return Modular
	}
	return invalidArithmeticType
}

func (ctx *ArithmeticContext) IsSigned() bool {
	return !ctx.Modular && !ctx.BottomAtZero && !ctx.BottomAtOne
}

func (ctx *ArithmeticContext) IsUnsignedPositive() bool {
	return !ctx.Modular && !ctx.BottomAtZero && ctx.BottomAtOne
}

func (ctx *ArithmeticContext) IsUnsigned() bool {
	return !ctx.Modular && ctx.BottomAtZero && !ctx.BottomAtOne
}

func (ctx *ArithmeticContext) IsModular() bool {
	return ctx.Modular && ctx.BottomAtZero && !ctx.BottomAtOne
}

func (ctx *ArithmeticContext) Validate() bool {
	return ctx.IsUnsignedPositive() || ctx.IsUnsigned() || ctx.IsSigned() || ctx.IsModular()
}

type NatValue interface {
	uint64 | *saferith.Nat
}

type NatPlusValue interface {
	uint64 | *saferith.Nat | *saferith.Modulus
}

type IntValue interface {
	int64 | *saferith.Int | *big.Int
}
