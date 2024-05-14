package impl

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	aimpl "github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

type ArithmeticMixin[T aimpl.ImplAdapter[T, Impl], Impl any] struct {
	Ctx *integer.ArithmeticContext
}

func (*ArithmeticMixin[T, I]) Cmp(x, y T) algebra.Ordering {
	panic("in mixin")
}

func (*ArithmeticMixin[T, I]) Zero() T {
	panic("in mixin")
}

func (*ArithmeticMixin[T, I]) One() T {
	panic("in mixin")
}

func (a *ArithmeticMixin[T, I]) Context() *integer.ArithmeticContext {
	return &integer.ArithmeticContext{
		Size:           a.Ctx.Size,
		Modulus:        a.Ctx.Modulus,
		BottomAtZero:   a.Ctx.BottomAtZero,
		BottomAtOne:    a.Ctx.BottomAtOne,
		ValidateInputs: a.Ctx.ValidateInputs,
	}
}

func (a *ArithmeticMixin[T, Impl]) Type() integer.ArithmeticType {
	return a.Context().Eval()
}

func (a *ArithmeticMixin[T, I]) anyZeros(xs ...T) bool {
	for _, x := range xs {
		if a.Cmp(x, a.Zero()) == algebra.Equal {
			return true
		}
	}
	return false
}

func (a *ArithmeticMixin[T, I]) validateInputs(xs ...T) error {
	if !a.Ctx.ValidateInputs {
		return nil
	}
	switch a.Type() {
	case integer.ForNPlus:
		for _, x := range xs {
			if a.Cmp(x, a.One()) == algebra.LessThan {
				return errs.NewValue("N+ element can't be less than 1")
			}
		}
	case integer.ForN:
		for _, x := range xs {
			if a.Cmp(x, a.Zero()) == algebra.LessThan {
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
	switch a.Type() {
	case integer.ForNPlus, integer.ForN:
		for _, x := range xs {
			if a.Cmp(x, a.One()) == algebra.LessThan {
				return errs.NewValue("denominator < 1")
			}
		}
	case integer.ForZ, integer.ForZn:
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
	if a.Type() == integer.ForN && a.Cmp(x, a.Zero()) != algebra.Equal {
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
	switch a.Type() {
	case integer.ForNPlus:
		if a.Cmp(x, y) == algebra.LessThan {
			return errs.NewValue("x < y")
		}
		if a.Cmp(x, a.One()) == algebra.LessThan {
			return errs.NewValue("y < 1")
		}
	case integer.ForN:
		if a.Cmp(x, y) == algebra.LessThan {
			return errs.NewValue("x < y")
		}
		if a.Cmp(x, a.Zero()) == algebra.LessThan {
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
