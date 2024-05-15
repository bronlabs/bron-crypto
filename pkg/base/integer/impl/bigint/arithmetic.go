package bigint

import (
	"math/big"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	aimpl "github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/impl"
)

var _ integer.Arithmetic[*NatPlus] = (*BigArithmetic[*NatPlus])(nil)

type BigArithmetic[T aimpl.ImplAdapter[T, *BigInt]] struct {
	impl.ArithmeticMixin[T, *BigInt]
	modulus T
}

func NewSignedArithmetic[T aimpl.ImplAdapter[T, *BigInt]](size int, validate bool) *BigArithmetic[T] {
	out := &BigArithmetic[T]{
		ArithmeticMixin: impl.ArithmeticMixin[T, *BigInt]{
			Ctx: &integer.ArithmeticContext{
				Size:           size,
				ValidateInputs: validate,
			},
		},
	}
	out.ArithmeticMixin.H = out
	return out
}

func NewUnsignedArithmetic[T aimpl.ImplAdapter[T, *BigInt]](size int, validate bool) *BigArithmetic[T] {
	out := &BigArithmetic[T]{
		ArithmeticMixin: impl.ArithmeticMixin[T, *BigInt]{
			Ctx: &integer.ArithmeticContext{
				BottomAtZero:   true,
				Size:           size,
				ValidateInputs: validate,
			},
		},
	}
	out.ArithmeticMixin.H = out
	return out
}

func NewModularArithmetic[T aimpl.ImplAdapter[T, *BigInt]](modulus T, size int, validate bool) *BigArithmetic[T] {
	m := modulus.Impl()
	if m == nil {
		panic(errs.NewIsNil("modulus"))
	}
	if m.Equal(Zero) {
		panic(errs.NewValue("modulus is zero"))
	}
	out := &BigArithmetic[T]{
		ArithmeticMixin: impl.ArithmeticMixin[T, *BigInt]{
			Ctx: &integer.ArithmeticContext{
				BottomAtZero:   true,
				Modulus:        m.Nat(),
				Size:           size,
				ValidateInputs: validate,
			},
		},
		modulus: modulus,
	}
	out.ArithmeticMixin.H = out
	return out
}

func NewNPlusArithmetic[T aimpl.ImplAdapter[T, *BigInt]](size int, validate bool) *BigArithmetic[T] {
	out := &BigArithmetic[T]{
		ArithmeticMixin: impl.ArithmeticMixin[T, *BigInt]{
			Ctx: &integer.ArithmeticContext{
				BottomAtOne:    true,
				Size:           size,
				ValidateInputs: validate,
			},
		},
	}
	out.ArithmeticMixin.H = out
	return out
}

func (*BigArithmetic[T]) new(x *BigInt) T {
	var t T
	return t.New(x)
}

func (*BigArithmetic[T]) Name() string {
	return Name
}

func (a *BigArithmetic[T]) WithoutBottom() integer.Arithmetic[T] {
	return NewSignedArithmetic[T](a.Ctx.Size, a.Ctx.ValidateInputs)
}

func (a *BigArithmetic[T]) WithBottomAtZero() integer.Arithmetic[T] {
	return NewUnsignedArithmetic[T](a.Ctx.Size, a.Ctx.ValidateInputs)
}

func (a *BigArithmetic[T]) WithBottomAtOne() integer.Arithmetic[T] {
	return NewNPlusArithmetic[T](a.Ctx.Size, a.Ctx.ValidateInputs)
}

func (a *BigArithmetic[T]) WithBottomAtZeroAndModulus(m T) integer.Arithmetic[T] {
	size := a.Ctx.Size
	if m.Impl().V.BitLen() > a.Ctx.Size {
		size = m.Impl().V.BitLen()
	}
	return NewModularArithmetic(m, size, a.Ctx.ValidateInputs)
}

func (a *BigArithmetic[T]) WithSize(size int) integer.Arithmetic[T] {
	if size < 0 {
		size = -1
	}
	ctx := a.Context()
	ctx.Size = size
	return &BigArithmetic[T]{
		ArithmeticMixin: impl.ArithmeticMixin[T, *BigInt]{
			Ctx: ctx,
		},
		modulus: a.modulus,
	}
}

func (a *BigArithmetic[T]) WithContext(ctx *integer.ArithmeticContext) integer.Arithmetic[T] {
	out := &BigArithmetic[T]{
		ArithmeticMixin: impl.ArithmeticMixin[T, *BigInt]{
			Ctx: a.Ctx,
		},
	}
	if ctx.Modulus != nil {
		out.modulus = a.new(new(BigInt).SetNat(ctx.Modulus))
	}
	return out
}

func (a *BigArithmetic[T]) WithoutInputValidation() integer.Arithmetic[T] {
	ctx := a.Context()
	ctx.ValidateInputs = false
	return a.WithContext(ctx)
}

func (a *BigArithmetic[T]) Equal(x, y T) bool {
	return a.Cmp(x, y) == algebra.Equal
}

func (a *BigArithmetic[T]) Cmp(x, y T) algebra.Ordering {
	return algebra.Ordering(x.Impl().V.Cmp(y.Impl().V))
}

func (a *BigArithmetic[T]) Zero() T {
	return a.new(Zero)
}

func (a *BigArithmetic[T]) One() T {
	return a.new(One)
}

func (a *BigArithmetic[T]) Two() T {
	return a.new(Two)
}

func (a *BigArithmetic[T]) IsEven(x T) bool {
	out, _ := a.WithoutBottom().Mod(x, a.Two())
	return a.Equal(out, a.One())
}

func (a *BigArithmetic[T]) IsOdd(x T) bool {
	return !a.IsEven(x)
}

func (a *BigArithmetic[T]) Abs(x T) T {
	return a.new(B(new(big.Int).Abs(x.Impl().V)))
}

func (a *BigArithmetic[T]) neg(x T) T {
	return a.new(B(new(big.Int).Neg(x.Impl().V)))
}

func (a *BigArithmetic[T]) Neg(x T) (T, error) {
	if err := a.ValidateNeg(x); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	switch a.Type() {
	case integer.ForNPlus:
		panic("should have errored out")
	case integer.ForN:
		return a.Zero(), nil
	case integer.ForZ:
		return a.neg(x), nil
	case integer.ForZn:
		return a.modInverse(x), nil
	default:
		return *new(T), errs.NewType("invalid arithmetic context")
	}
}

func (a *BigArithmetic[T]) modInverse(x T) T {
	return a.new(B(new(big.Int).ModInverse(x.Impl().V, a.modulus.Impl().V)))
}

func (a *BigArithmetic[T]) Inverse(x T) (T, error) {
	if err := a.ValidateInverse(x); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	if a.Equal(x, a.One()) {
		return a.One(), nil
	}
	switch a.Type() {
	case integer.ForZn:
		return a.modInverse(x), nil
	default:
		return *new(T), errs.NewType("invalid arithmetic context")
	}
}

func (a *BigArithmetic[T]) add(x, y T) T {
	return a.new(B(new(big.Int).Add(x.Impl().V, y.Impl().V)))
}

func (a *BigArithmetic[T]) Add(x, y T) (T, error) {
	if err := a.ValidateAdd(x); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	xy := a.add(x, y)
	if a.Type() == integer.ForZn {
		xy = a.mod(xy, a.modulus)
	}
	return xy, nil
}

func (a *BigArithmetic[T]) sub(x, y T) T {
	return a.new(B(new(big.Int).Sub(x.Impl().V, y.Impl().V)))
}

func (a *BigArithmetic[T]) Sub(x, y T) (T, error) {
	if err := a.ValidateSub(x, y); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	xy := a.sub(x, y)
	if a.Type() == integer.ForZn {
		xy = a.mod(xy, a.modulus)
	}
	return xy, nil
}

func (a *BigArithmetic[T]) mul(x, y T) T {
	return a.new(B(new(big.Int).Mul(x.Impl().V, y.Impl().V)))
}

func (a *BigArithmetic[T]) Mul(x, y T) (T, error) {
	if err := a.ValidateMul(x); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	xy := a.mul(x, y)
	if a.Type() == integer.ForZn {
		xy = a.mod(xy, a.modulus)
	}
	return xy, nil
}

func (a *BigArithmetic[T]) div(x, y T) T {
	return a.new(B(new(big.Int).Div(x.Impl().V, y.Impl().V)))
}

func (a *BigArithmetic[T]) Div(x, y T) (T, error) {
	if err := a.ValidateDiv(x, y); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	xy := a.div(x, y)
	if a.Type() == integer.ForZn {
		xy = a.mod(xy, a.modulus)
	}
	return xy, nil
}

func (a *BigArithmetic[T]) exp(x, y T) T {
	return a.new(B(new(big.Int).Exp(x.Impl().V, y.Impl().V, nil)))
}

func (a *BigArithmetic[T]) modExp(x, y, m T) T {
	return a.new(B(new(big.Int).Exp(x.Impl().V, y.Impl().V, m.Impl().V)))
}

func (a *BigArithmetic[T]) Exp(x, y T) (T, error) {
	if err := a.ValidateExp(x, y); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	if a.Type() == integer.ForZn {
		return a.modExp(x, y, a.modulus), nil
	}
	return a.exp(x, y), nil
}

func (a *BigArithmetic[T]) mod(x, m T) T {
	return a.new(B(new(big.Int).Mod(x.Impl().V, m.Impl().V)))
}

func (a *BigArithmetic[T]) Mod(x, m T) (T, error) {
	if err := a.ValidateMod(x, m); err != nil {
		return *new(T), errs.WrapValidation(err, "invalid argument")
	}
	xm := a.mod(x, m)
	if a.Type() == integer.ForZn && !a.Equal(m, a.modulus) {
		xm = a.mod(xm, a.modulus)
	}
	return xm, nil
}

func (a *BigArithmetic[T]) Uint64(x T) uint64 {
	return x.Impl().Uint64()
}
