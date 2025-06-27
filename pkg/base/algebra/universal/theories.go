package universal

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

func Void[C CarrierSet[E], E Element[E]](c C) Theory[C, E] {
	return Theory[C, E]{
		CarrierSet: c,
		Signature: Signature[E]{
			Nullary: map[Constant]E{},
			Unary:   []UnaryOperator[E]{},
			Binary:  []BinaryOperator[E]{},
		},
		Axiom: Axioms[E]{
			Unary:   []UnaryProperty[E]{},
			Binary:  []BinaryProperty[E]{},
			Ternary: []TernaryProperty[E]{},
		},
	}
}

func Magma[C CarrierSet[E], E Element[E]](set C, op BinaryOperator[E]) Theory[C, E] {
	t := Void(set)
	t.Signature.Binary = append(t.Signature.Binary, op)
	return t
}

func SemiGroup[C CarrierSet[E], E Element[E]](set C, op BinaryOperator[E]) Theory[C, E] {
	t := Magma(set, op)
	t.Axiom.Ternary = append(t.Axiom.Ternary, op.IsAssociative)
	return t
}

func Monoid[C CarrierSet[E], E Element[E]](set C, op BinaryOperator[E], id E) Theory[C, E] {
	t := SemiGroup(set, op)
	name := Identity
	if op.Name() == AdditionType {
		name = Zero
	}
	if op.Name() == MultiplicationType {
		name = One
	}
	t.Signature.Nullary[name] = id
	t.Axiom.Unary = append(t.Axiom.Unary, func(x E) bool {
		return op.IsIdentity(id, x)
	})
	return t
}

func Group[C CarrierSet[E], E Element[E]](set C, op BinaryOperator[E], id E, inv UnaryOperator[E]) Theory[C, E] {
	t := Monoid(set, op, id)
	t.Signature.Unary = append(t.Signature.Unary, inv)
	t.Axiom.Unary = append(t.Axiom.Unary, func(x E) bool {
		return op.IsInverse(inv.Apply(x), id, x)
	})
	return t
}

func DoubleMagma[C CarrierSet[E], E Element[E]](set C, op1, op2 BinaryOperator[E]) Theory[C, E] {
	t1 := Magma(set, op1)
	t2 := Magma(set, op2)
	t := ExpandTheory(t1, t2)
	t.Axiom.Ternary = append(t.Axiom.Ternary, func(x, y, z E) bool {
		return op2.IsDistributive(op1, x, y, z)
	})
	return t
}

func HemiRing[C CarrierSet[E], E Element[E]](set C, op1, op2 BinaryOperator[E]) Theory[C, E] {
	t1 := SemiGroup(set, op1)
	t2 := SemiGroup(set, op2)
	t := ExpandTheory(t1, t2)
	t.Axiom.Ternary = append(t.Axiom.Ternary, func(x, y, z E) bool {
		return op2.IsDistributive(op1, x, y, z)
	})
	return t
}

func SemiRing[C CarrierSet[E], E Element[E]](set C, add, mul BinaryOperator[E], one E) Theory[C, E] {
	t1 := HemiRing(set, add, mul)
	t2 := Monoid(set, mul, one)
	t := ExpandTheory(t1, t2)
	return t
}

func Rig[C CarrierSet[E], E Element[E]](set C, add, mul BinaryOperator[E], zero, one E) Theory[C, E] {
	t1 := SemiRing(set, add, mul, one)
	t2 := Monoid(set, add, zero)
	t := ExpandTheory(t1, t2)
	t.Axiom.Unary = append(t.Axiom.Unary, func(x E) bool {
		return mul.IsInverse(one, zero, x)
	})
	return t
}

func Rng[C CarrierSet[E], E Element[E]](set C, add, mul BinaryOperator[E], zero, one E, additiveInverse UnaryOperator[E]) Theory[C, E] {
	t1 := HemiRing(set, add, mul)
	t2 := Group(set, add, zero, additiveInverse)
	t := ExpandTheory(t1, t2)
	return t
}

func Ring[C CarrierSet[E], E Element[E]](set C, add, mul BinaryOperator[E], zero, one E, additiveInverse UnaryOperator[E]) Theory[C, E] {
	t1 := Rig(set, add, mul, zero, one)
	t2 := Rng(set, add, mul, zero, one, additiveInverse)
	t := ExpandTheory(t1, t2)
	return t
}

func Field[C CarrierSet[E], E Element[E]](set C, add, mul BinaryOperator[E], zero, one E, additiveInverse, multiplicativeInverse UnaryOperator[E]) Theory[C, E] {
	t := Ring(set, add, mul, zero, one, additiveInverse)
	t, _ = MakeAbelian(t, add, mul)
	nonZero := UnaryOperator[E]{
		name: multiplicativeInverse.name,
		op: func(x E) E {
			if x.Equal(zero) {
				panic(errs.NewValue("cannot apply multiplicative inverse to zero"))
			}
			return multiplicativeInverse.Apply(x)
		},
	}
	t.Signature.Unary = append(t.Signature.Unary, nonZero)

	return t
}

func Module[C1 CarrierSet[E1], C2 CarrierSet[E2], E1 Element[E1], E2 Element[E2]](
	mset C1, mop BinaryOperator[E1], mid E1, minv UnaryOperator[E1],
	rset C2, radd BinaryOperator[E2], rmul BinaryOperator[E2], rzero E2, rone E2, rneg UnaryOperator[E2],
	smul MixedSortedBinaryOperator[E1, E2],
) TwoSortedTheory[C1, C2, E1, E2] {
	group, _ := MakeAbelian(Group(mset, mop, mid, minv), mop)
	scalarRing := Ring(rset, radd, rmul, rzero, rone, rneg)

	mixedSignature := MixedSignature[E1, E2]{
		Binary: []MixedSortedBinaryOperator[E1, E2]{smul},
	}
	// Left distributivity over vector addition
	// right distributivity over scalar addition
	// mixed associativity
	// unit acts as identity
	// zeros map to module
	module := NewTwoSortedTheory(group, scalarRing, mixedSignature, MixedAxioms[E1, E2]{})
	return module
}

func VectorSpace[C1 CarrierSet[E1], C2 CarrierSet[E2], E1 Element[E1], E2 Element[E2]](
	mset C1, mop BinaryOperator[E1], mid E1, minv UnaryOperator[E1],
	fset C2, fadd BinaryOperator[E2], fmul BinaryOperator[E2], fzero E2, fone E2, fneg UnaryOperator[E2], finv UnaryOperator[E2],
	smul MixedSortedBinaryOperator[E1, E2],
) TwoSortedTheory[C1, C2, E1, E2] {
	group, _ := MakeAbelian(Group(mset, mop, mid, minv), mop)
	scalarField := Field(fset, fadd, fmul, fzero, fone, fneg, finv)

	mixedSignature := MixedSignature[E1, E2]{
		Binary: []MixedSortedBinaryOperator[E1, E2]{smul},
	}
	// Left distributivity over vector addition
	// right distributivity over scalar addition
	// mixed associativity
	// unit acts as identity
	// zeros map to module
	module := NewTwoSortedTheory(group, scalarField, mixedSignature, MixedAxioms[E1, E2]{})
	return module
}
