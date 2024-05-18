package impl

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	aimpl "github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/cronokirby/saferith"
)

type HolesArithmeticMixin[T aimpl.ImplAdapter[T, Impl], Impl any] interface {
	Cmp(x, y T) algebra.Ordering
	Zero() T
	One() T
}

type ArithmeticMixin[T aimpl.ImplAdapter[T, Impl], Impl any] struct {
	Ctx *ArithmeticContext
	H   HolesArithmeticMixin[T, Impl]
}

func (a *ArithmeticMixin[T, I]) anyZeros(xs ...T) bool {
	for _, x := range xs {
		if a.H.Cmp(x, a.H.Zero()) == algebra.Equal {
			return true
		}
	}
	return false
}

func (a *ArithmeticMixin[T, I]) validateInputs(xs ...T) error {
	if !a.Ctx.ValidateInputs {
		return nil
	}
	switch a.Ctx.Type() {
	case UnsignedPositive:
		for _, x := range xs {
			if a.H.Cmp(x, a.H.One()) == algebra.LessThan {
				return errs.NewValue("N+ element can't be less than 1")
			}
		}
	case Unsigned:
		for _, x := range xs {
			if a.H.Cmp(x, a.H.Zero()) == algebra.LessThan {
				return errs.NewValue("N element can't be less than 0")
			}
		}
	}
	return nil
}

func (a *ArithmeticMixin[T, I]) validateDenominator(xs ...T) error {
	if !a.Ctx.ValidateInputs {
		return nil
	}
	switch a.Ctx.Type() {
	case UnsignedPositive, Unsigned:
		for _, x := range xs {
			if a.H.Cmp(x, a.H.One()) == algebra.LessThan {
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

func (a *ArithmeticMixin[T, I]) validateModulus(xs ...T) error {
	if !a.Ctx.ValidateInputs {
		return nil
	}
	if someAreZero := a.anyZeros(xs...); someAreZero {
		return errs.NewValue("moduli can't be less than 1")
	}
	return nil
}

func (a *ArithmeticMixin[T, I]) ValidateNeg(x T) error {
	if !a.Ctx.ValidateInputs {
		return nil
	}
	if err := a.validateInputs(x); err != nil {
		return errs.WrapValidation(err, "invalid argument")
	}
	if a.Ctx.Type() == Unsigned && a.H.Cmp(x, a.H.Zero()) != algebra.Equal {
		return errs.NewValue("can only negate 0 in N")
	}
	return nil
}

func (a *ArithmeticMixin[T, I]) ValidateInverse(x T) error {
	return a.validateDenominator(x)
}

func (a *ArithmeticMixin[T, I]) ValidateAdd(x T) error {
	return a.validateInputs(x)
}

func (a *ArithmeticMixin[T, I]) ValidateSub(x, y T) error {
	if !a.Ctx.ValidateInputs {
		return nil
	}
	switch a.Ctx.Type() {
	case UnsignedPositive:
		if a.H.Cmp(x, y) == algebra.LessThan {
			return errs.NewValue("x < y")
		}
		if a.H.Cmp(x, a.H.One()) == algebra.LessThan {
			return errs.NewValue("y < 1")
		}
	case Unsigned:
		if a.H.Cmp(x, y) == algebra.LessThan {
			return errs.NewValue("x < y")
		}
		if a.H.Cmp(x, a.H.Zero()) == algebra.LessThan {
			return errs.NewValue("x < 0")
		}
	}
	return nil
}

func (a *ArithmeticMixin[T, I]) ValidateMul(x T) error {
	return a.validateInputs(x)
}

func (a *ArithmeticMixin[T, I]) ValidateDiv(x, y T) error {
	if err := a.validateInputs(x); err != nil {
		return errs.WrapValidation(err, "invalid numerator")
	}
	if err := a.validateDenominator(x); err != nil {
		return errs.WrapValidation(err, "invalid denominator")
	}
	return nil
}

func (a *ArithmeticMixin[T, I]) ValidateExp(x, y T) error {
	return a.validateInputs(x, y)
}

func (a *ArithmeticMixin[T, I]) ValidateMod(x, m T) error {
	if err := a.validateInputs(x); err != nil {
		return errs.WrapValidation(err, "invalid numerator")
	}
	if err := a.validateModulus(x); err != nil {
		return errs.WrapValidation(err, "invalid modulus")
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
	Modulus        *saferith.Nat
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
	return ctx.Modulus == nil && !ctx.BottomAtZero && !ctx.BottomAtOne
}

func (ctx *ArithmeticContext) IsUnsignedPositive() bool {
	return ctx.Modulus == nil && !ctx.BottomAtZero && ctx.BottomAtOne
}

func (ctx *ArithmeticContext) IsUnsigned() bool {
	return ctx.Modulus == nil && ctx.BottomAtZero && !ctx.BottomAtOne
}

func (ctx *ArithmeticContext) IsModular() bool {
	return ctx.Modulus != nil && ctx.Modulus.EqZero() != 1 && ctx.BottomAtZero && !ctx.BottomAtOne
}

func (ctx *ArithmeticContext) Validate() bool {
	return ctx.IsUnsignedPositive() || ctx.IsUnsigned() || ctx.IsSigned() || ctx.IsModular()
}
