package model

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

type Law string

type Property interface {
	Law() Law
}

type Property1[E Element[E]] interface {
	Property
	Check(E) bool
}

type Property2[E Element[E]] interface {
	Property
	Check(E, E) bool
}

type Property3[E Element[E]] interface {
	Property
	Check(E, E, E) bool
}

func ClosureLaw[E Element[E]](set CarrierSet[E], op Function[E]) Law {
	return Law(fmt.Sprintf("%s is closed under %s", set.Symbol(), op.Symbol()))
}

type ClosureProperty1[E Element[E]] struct {
	set CarrierSet[E]
	op  *UnaryOperator[E]
}

func (p *ClosureProperty1[E]) Law() Law {
	return ClosureLaw(p.set, p.op)
}

func (p *ClosureProperty1[E]) Check(x E) bool {
	defer func() {
		if r := recover(); r != nil {
			panic(errs.NewFailed("operator is not closed: %s", r))
		}
	}()
	return !utils.IsNil(p.op.call(x))
}

type ClosureProperty2[E Element[E]] struct {
	set CarrierSet[E]
	op  *BinaryOperator[E]
}

func (p *ClosureProperty2[E]) Law() Law {
	return ClosureLaw(p.set, p.op)
}

func (p *ClosureProperty2[E]) Check(x, y E) bool {
	defer func() {
		if r := recover(); r != nil {
			panic(errs.NewFailed("operator is not closed: %s", r))
		}
	}()
	return !utils.IsNil(p.op.call(x, y))
}

func AssociativeLaw[E Element[E]](set CarrierSet[E], op *BinaryOperator[E]) Law {
	return Law(fmt.Sprintf("%s is associative on %s", op.Symbol(), set.Symbol()))
}

type AssociativeProperty[E Element[E]] struct {
	set CarrierSet[E]
	op  *BinaryOperator[E]
}

func (p *AssociativeProperty[E]) Law() Law {
	return AssociativeLaw(p.set, p.op)
}

func (p *AssociativeProperty[E]) Check(x, y, z E) bool {
	return p.op.call(x, p.op.call(y, z)).Equal(p.op.call(p.op.call(x, y), z))
}

func LeftIdentityElementLaw[E Element[E]](set CarrierSet[E], op *BinaryOperator[E], id *Constant[E]) Law {
	return Law(fmt.Sprintf("%s admits left identity element %s under %s", set.Symbol(), id.Symbol(), op.Symbol()))
}

type LeftIdentityElementProperty[E Element[E]] struct {
	set CarrierSet[E]
	op  *BinaryOperator[E]
	id  *Constant[E]
}

func (p *LeftIdentityElementProperty[E]) Law() Law {
	return LeftIdentityElementLaw(p.set, p.op, p.id)
}

func (p *LeftIdentityElementProperty[E]) Check(x E) bool {
	return p.op.call(p.id.value, x).Equal(x)
}

func RightIdentityElementLaw[E Element[E]](set CarrierSet[E], op *BinaryOperator[E], id *Constant[E]) Law {
	return Law(fmt.Sprintf("%s admits right identity element %s under %s", set.Symbol(), id.Symbol(), op.Symbol()))
}

type RightIdentityElementProperty[E Element[E]] struct {
	set CarrierSet[E]
	op  *BinaryOperator[E]
	id  *Constant[E]
}

func (p *RightIdentityElementProperty[E]) Law() Law {
	return RightIdentityElementLaw(p.set, p.op, p.id)
}

func (p *RightIdentityElementProperty[E]) Check(x E) bool {
	return p.op.call(x, p.id.value).Equal(x)
}

func IdentityElementLaw[E Element[E]](set CarrierSet[E], op *BinaryOperator[E], id *Constant[E]) Law {
	return Law(fmt.Sprintf("%s admits identity element %s under %s", set.Symbol(), id.Symbol(), op.Symbol()))
}

type IdentityElementProperty[E Element[E]] struct {
	set CarrierSet[E]
	op  *BinaryOperator[E]
	id  *Constant[E]
}

func (p *IdentityElementProperty[E]) Law() Law {
	return IdentityElementLaw(p.set, p.op, p.id)
}

func (p *IdentityElementProperty[E]) Check(x E) bool {
	left := &LeftIdentityElementProperty[E]{
		set: p.set,
		op:  p.op,
		id:  p.id,
	}
	right := &RightIdentityElementProperty[E]{
		set: p.set,
		op:  p.op,
		id:  p.id,
	}
	return left.Check(x) && right.Check(x)
}

func LeftInverseElementLaw[E Element[E]](set CarrierSet[E], op *BinaryOperator[E], inv *UnaryOperator[E], id *Constant[E]) Law {
	return Law(fmt.Sprintf("%s admits left-inverse element %s under %s with respect to %s", set.Symbol(), inv.Symbol(), op.Symbol(), id.Symbol()))
}

type LeftInverseElementProperty[E Element[E]] struct {
	set CarrierSet[E]
	op  *BinaryOperator[E]
	inv *UnaryOperator[E]
	id  *Constant[E]
}

func (p *LeftInverseElementProperty[E]) Law() Law {
	return LeftInverseElementLaw(p.set, p.op, p.inv, p.id)
}

func (p *LeftInverseElementProperty[E]) Check(x E) bool {
	return p.op.call(p.inv.call(x), x).Equal(p.id.value)
}

func RightInverseElementLaw[E Element[E]](set CarrierSet[E], op *BinaryOperator[E], inv *UnaryOperator[E], id *Constant[E]) Law {
	return Law(fmt.Sprintf("%s admits right-inverse element %s under %s with respect to %s", set.Symbol(), inv.Symbol(), op.Symbol(), id.Symbol()))
}

type RightInverseElementProperty[E Element[E]] struct {
	set CarrierSet[E]
	op  *BinaryOperator[E]
	inv *UnaryOperator[E]
	id  *Constant[E]
}

func (p *RightInverseElementProperty[E]) Law() Law {
	return RightInverseElementLaw(p.set, p.op, p.inv, p.id)
}

func (p *RightInverseElementProperty[E]) Check(x E) bool {
	return p.op.call(x, p.inv.call(x)).Equal(p.id.value)
}

func InverseElementLaw[E Element[E]](set CarrierSet[E], op *BinaryOperator[E], inv *UnaryOperator[E], id *Constant[E]) Law {
	return Law(fmt.Sprintf("%s admits inverse element %s under %s with respect to %s", set.Symbol(), inv.Symbol(), op.Symbol(), id.Symbol()))
}

type InverseElementProperty[E Element[E]] struct {
	set CarrierSet[E]
	op  *BinaryOperator[E]
	inv *UnaryOperator[E]
	id  *Constant[E]
}

func (p *InverseElementProperty[E]) Law() Law {
	return InverseElementLaw(p.set, p.op, p.inv, p.id)
}

func (p *InverseElementProperty[E]) Check(x E) bool {
	left := &LeftInverseElementProperty[E]{
		set: p.set,
		op:  p.op,
		inv: p.inv,
		id:  p.id,
	}
	right := &RightInverseElementProperty[E]{
		set: p.set,
		op:  p.op,
		inv: p.inv,
		id:  p.id,
	}
	return left.Check(x) && right.Check(x)
}

func CommutativeLaw[E Element[E]](set CarrierSet[E], op *BinaryOperator[E]) Law {
	return Law(fmt.Sprintf("%s is commutative on %s", op.Symbol(), set.Symbol()))
}

type CommutativeProperty[E Element[E]] struct {
	set CarrierSet[E]
	op  *BinaryOperator[E]
}

func (p *CommutativeProperty[E]) Law() Law {
	return CommutativeLaw(p.set, p.op)
}

func (p *CommutativeProperty[E]) Check(x, y E) bool {
	return p.op.call(x, y).Equal(p.op.call(y, x))
}

func LeftDistributivityLaw[E Element[E]](set CarrierSet[E], op *BinaryOperator[E], over *BinaryOperator[E]) Law {
	return Law(fmt.Sprintf("%s is left-distributive over %s on %s", op.Symbol(), over.Symbol(), set.Symbol()))
}

type LeftDistributiveProperty[E Element[E]] struct {
	set  CarrierSet[E]
	op   *BinaryOperator[E]
	over *BinaryOperator[E]
}

func (p *LeftDistributiveProperty[E]) Law() Law {
	return LeftDistributivityLaw(p.set, p.op, p.over)
}

func (p *LeftDistributiveProperty[E]) Check(x, y, z E) bool {
	return p.op.call(x, p.over.call(y, z)).Equal(p.over.call(p.op.call(x, y), p.op.call(x, z)))
}

func RightDistributivityLaw[E Element[E]](set CarrierSet[E], op *BinaryOperator[E], over *BinaryOperator[E]) Law {
	return Law(fmt.Sprintf("%s is right-distributive over %s on %s", op.Symbol(), over.Symbol(), set.Symbol()))
}

type RightDistributiveProperty[E Element[E]] struct {
	set  CarrierSet[E]
	op   *BinaryOperator[E]
	over *BinaryOperator[E]
}

func (p *RightDistributiveProperty[E]) Law() Law {
	return RightDistributivityLaw(p.set, p.op, p.over)
}

func (p *RightDistributiveProperty[E]) Check(x, y, z E) bool {
	return p.op.call(p.over.call(x, y), z).Equal(p.over.call(p.op.call(x, z), p.op.call(y, z)))
}

func DistributivityLaw[E Element[E]](set CarrierSet[E], op *BinaryOperator[E], over *BinaryOperator[E]) Law {
	return Law(fmt.Sprintf("%s is distributive over %s on %s", op.Symbol(), over.Symbol(), set.Symbol()))
}

type DistributiveProperty[E Element[E]] struct {
	set  CarrierSet[E]
	op   *BinaryOperator[E]
	over *BinaryOperator[E]
}

func (p *DistributiveProperty[E]) Law() Law {
	return DistributivityLaw(p.set, p.op, p.over)
}

func (p *DistributiveProperty[E]) Check(x, y, z E) bool {
	left := &LeftDistributiveProperty[E]{
		set:  p.set,
		op:   p.op,
		over: p.over,
	}
	right := &RightDistributiveProperty[E]{
		set:  p.set,
		op:   p.op,
		over: p.over,
	}
	return left.Check(x, y, z) && right.Check(x, y, z)
}

// import (
// 	"reflect"

// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// 	"github.com/bronlabs/bron-crypto/pkg/base/utils"
// )

// type UnaryOperator[E Element[E]] func(E) E

// func (u UnaryOperator[E]) IsClosed(x E) bool {
// 	defer func() {
// 		if r := recover(); r != nil {
// 			panic(errs.NewFailed("operator is not closed: %s", r))
// 		}
// 	}()
// 	return !utils.IsNil(u(x))
// }

// func (u UnaryOperator[E]) IsIdempotent(x E) bool {
// 	return u(u(x)).Equal(u(x))
// }

// func (u UnaryOperator[E]) IsInvolution(x E) bool {
// 	return x.Equal(u(u(x)))
// }

// func (u UnaryOperator[E]) IsFixedPoint(x E) bool {
// 	return x.Equal(u(x))
// }

// func (u UnaryOperator[E]) IsConstant(candidate, x E) bool {
// 	return u(x).Equal(candidate)
// }

// type BinaryOperator[E Element[E]] func(E, E) E

// func (b BinaryOperator[E]) IsClosed(x, y E) bool {
// 	defer func() {
// 		if r := recover(); r != nil {
// 			panic(errs.NewFailed("operator is not closed: %s", r))
// 		}
// 	}()
// 	return !utils.IsNil(b(x, y))
// }

// func (f BinaryOperator[E]) IsCommutative(a, b E) bool {
// 	return f(a, b).Equal(f(b, a))
// }

// func (f BinaryOperator[E]) IsFlexible(x, y E) bool {
// 	return f(x, f(y, x)).Equal(f(f(x, y), x))
// }

// func (f BinaryOperator[E]) IsLeftAlternative(x, y E) bool {
// 	return f(f(x, x), y).Equal(f(x, f(x, y)))
// }

// func (f BinaryOperator[E]) IsRightAlternative(x, y E) bool {
// 	return f(y, f(x, x)).Equal(f(f(y, x), x))
// }

// func (f BinaryOperator[E]) IsAlternative(x, y E) bool {
// 	return f.IsLeftAlternative(x, y) && f.IsRightAlternative(x, y)
// }

// func (f BinaryOperator[E]) IsPowerAssociative(x E, n uint) bool {
// 	left := leftPower(f, x, n)
// 	right := rightPower(f, x, n)
// 	return left.Equal(right)
// }

// func (f BinaryOperator[E]) IsAssociative(a, b, c E) bool {
// 	return foldLeft(f, a, b, c).Equal(foldRight(f, a, b, c))
// }

// func (f BinaryOperator[E]) IsIdempotent(x E) bool {
// 	return f(x, x).Equal(x)
// }

// func (f BinaryOperator[E]) IsLeftCancellative(candidate, x, y E) bool {
// 	return materialConditional(f(candidate, x).Equal(f(candidate, y)), x.Equal(y))
// }

// func (f BinaryOperator[E]) IsRightCancellative(candidate, x, y E) bool {
// 	return materialConditional(f(x, candidate).Equal(f(y, candidate)), x.Equal(y))
// }

// func (f BinaryOperator[E]) IsCancellative(candidate, x, y E) bool {
// 	return f.IsLeftCancellative(candidate, x, y) && f.IsRightCancellative(candidate, x, y)
// }

// func (f BinaryOperator[E]) IsLeftAbsorbing(candidate, x E) bool {
// 	return f(candidate, x).Equal(candidate)
// }

// func (f BinaryOperator[E]) IsRightAbsorbing(candidate, x E) bool {
// 	return f(x, candidate).Equal(candidate)
// }

// func (f BinaryOperator[E]) IsAbsorbing(candidate, x E) bool {
// 	return f.IsLeftAbsorbing(candidate, x) && f.IsRightAbsorbing(candidate, x)
// }

// func (f BinaryOperator[E]) IsLeftIdentity(candidate, x E) bool {
// 	return f(candidate, x).Equal(x)
// }

// func (f BinaryOperator[E]) IsRightIdentity(candidate, x E) bool {
// 	return f(x, candidate).Equal(x)
// }

// func (f BinaryOperator[E]) IsIdentity(candidate, x E) bool {
// 	return f.IsLeftIdentity(candidate, x) && f.IsRightIdentity(candidate, x)
// }

// func (f BinaryOperator[E]) IsLeftInverse(candidate, identity, x E) bool {
// 	return f(candidate, x).Equal(identity)
// }

// func (f BinaryOperator[E]) IsRightInverse(candidate, identity, x E) bool {
// 	return f(x, candidate).Equal(identity)
// }

// func (f BinaryOperator[E]) IsInverse(candidate, identity, x E) bool {
// 	return f.IsLeftInverse(candidate, identity, x) && f.IsRightInverse(candidate, identity, x)
// }

// func (f BinaryOperator[E]) IsLeftDistributive(over BinaryOperator[E], x, y, z E) bool {
// 	return f(x, over(y, z)).Equal(over(f(x, y), f(x, z)))
// }

// func (f BinaryOperator[E]) IsRightDistributive(over BinaryOperator[E], x, y, z E) bool {
// 	return f(over(x, y), z).Equal(over(f(x, z), f(y, z)))
// }

// func (f BinaryOperator[E]) IsDistributive(over BinaryOperator[E], x, y, z E) bool {
// 	return f.IsLeftDistributive(over, x, y, z) && f.IsRightDistributive(over, x, y, z)
// }

// type MixedSortedBinaryOperator[E1 Element[E1], E2 Element[E2]] func(E1, E2) E2

// func (m MixedSortedBinaryOperator[E1, E2]) IsClosed(x E1, y E2) bool {
// 	defer func() {
// 		if r := recover(); r != nil {
// 			panic(errs.NewFailed("operator is not closed: %s", r))
// 		}
// 	}()
// 	return !utils.IsNil(m(x, y))
// }

// func (f MixedSortedBinaryOperator[E1, E2]) IsLeftDistributive(over BinaryOperator[E2], x E1, y, z E2) bool {
// 	return f(x, over(y, z)).Equal(over(f(x, y), f(x, z)))
// }

// func (f MixedSortedBinaryOperator[E1, E2]) IsRightDistributive(over BinaryOperator[E1], homOver BinaryOperator[E2], x, y E1, z E2) bool {
// 	return f(over(x, y), z).Equal(homOver(f(x, z), f(y, z)))
// }

// // ******* Misc

// func RestrictUnaryOperator[E Element[E]](f UnaryOperator[E], predicate func(E) bool) UnaryOperator[E] {
// 	return UnaryOperator[E](func(x E) E {
// 		if !predicate(x) {
// 			panic(errs.NewValue("argument does not satisfy the predicate"))
// 		}
// 		return f(x)
// 	})
// }

// func LeftSection[E Element[E]](f BinaryOperator[E], x E) UnaryOperator[E] {
// 	return UnaryOperator[E](func(y E) E { return f(x, y) })
// }

// func RightSection[E Element[E]](f BinaryOperator[E], x E) UnaryOperator[E] {
// 	return UnaryOperator[E](func(y E) E { return f(y, x) })
// }

// func leftPower[E Element[E]](f BinaryOperator[E], x E, n uint) E {
// 	if n == 0 {
// 		panic("power must be greater than or equal to 1")
// 	}
// 	result := x
// 	for i := 1; i < int(n); i++ {
// 		result = f(result, x)
// 	}
// 	return result
// }

// func rightPower[E Element[E]](f BinaryOperator[E], x E, n uint) E {
// 	if n == 0 {
// 		panic("power must be greater than or equal to 1")
// 	}
// 	result := x
// 	for i := 1; i < int(n); i++ {
// 		result = f(x, result)
// 	}
// 	return result
// }

// func foldLeft[E Element[E]](f BinaryOperator[E], xs ...E) E {
// 	if len(xs) == 0 {
// 		return *new(E)
// 	}
// 	result := xs[0]
// 	for _, x := range xs[1:] {
// 		result = f(result, x)
// 	}
// 	return result
// }

// func foldRight[E Element[E]](f BinaryOperator[E], xs ...E) E {
// 	if len(xs) == 0 {
// 		return *new(E)
// 	}
// 	result := xs[len(xs)-1]
// 	for i := len(xs) - 2; i >= 0; i-- {
// 		result = f(xs[i], result)
// 	}
// 	return result
// }

// func materialConditional(p, q bool) bool {
// 	return !p || q
// }

// func equalOp(f, g any) bool {
// 	return reflect.ValueOf(f).Pointer() == reflect.ValueOf(g).Pointer()
// }
