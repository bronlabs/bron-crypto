package integer

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/cronokirby/saferith"
)

type Arithmetic[T any] interface {
	Name() string
	Type() ArithmeticType

	Context() *ArithmeticContext

	WithContext(ctx *ArithmeticContext) Arithmetic[T]
	WithoutBottom() Arithmetic[T]
	WithBottomAtZero() Arithmetic[T]
	WithBottomAtOne() Arithmetic[T]
	WithBottomAtZeroAndModulus(m T) Arithmetic[T]
	WithSize(size int) Arithmetic[T]
	WithoutInputValidation() Arithmetic[T]

	Equal(x, y T) bool

	Cmp(x, y T) algebra.Ordering

	Zero() T
	One() T
	Two() T

	IsEven(x T) bool
	IsOdd(x T) bool

	Abs(x T) T
	Neg(x T) (T, error)
	Inverse(x T) (T, error)

	Add(x, y T) (T, error)
	Sub(x, y T) (T, error)
	Mul(x, y T) (T, error)
	Exp(x, y T) (T, error)

	Mod(x, m T) (T, error)

	Uint64(x T) uint64
}

type Number[T any] interface {
	Arithmetic() Arithmetic[T]

	AnnouncedLen() int
	TrueLen() uint

	algebra.WrappedElement[T]
	algebra.NatLike[T]
}

type ArithmeticType string

const (
	ForZ                  ArithmeticType = "Z"
	ForNPlus              ArithmeticType = "N+"
	ForN                  ArithmeticType = "N"
	ForZn                 ArithmeticType = "Zn"
	invalidArithmeticType ArithmeticType = "<INVALID>"
)

type ArithmeticContext struct {
	BottomAtZero   bool
	BottomAtOne    bool
	Modulus        *saferith.Nat
	Size           int
	ValidateInputs bool
}

func (ctx *ArithmeticContext) Eval() ArithmeticType {
	if ctx.IsForZ() {
		return ForZ
	}
	if ctx.IsForNPlus() {
		return ForNPlus
	}
	if ctx.IsForN() {
		return ForN
	}
	if ctx.IsForZn() {
		return ForZn
	}
	return invalidArithmeticType
}

func (ctx *ArithmeticContext) IsForZ() bool {
	return ctx.Modulus == nil && !ctx.BottomAtZero && !ctx.BottomAtOne
}

func (ctx *ArithmeticContext) IsForNPlus() bool {
	return ctx.Modulus == nil && !ctx.BottomAtZero && ctx.BottomAtOne
}

func (ctx *ArithmeticContext) IsForN() bool {
	return ctx.Modulus == nil && ctx.BottomAtZero && !ctx.BottomAtOne
}

func (ctx *ArithmeticContext) IsForZn() bool {
	return ctx.Modulus != nil && ctx.Modulus.EqZero() != 1 && ctx.BottomAtZero && !ctx.BottomAtOne
}

func (ctx *ArithmeticContext) Validate() bool {
	return ctx.IsForNPlus() || ctx.IsForN() || ctx.IsForZ() || ctx.IsForZn()
}
