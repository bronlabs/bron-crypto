package model

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

func NewEmpty[E Element[E]]() *Model[E] {
	algebra, _ := newPureSet(NewEmptyCarrierSet[E]())
	theory, _ := NewTheory(NewEmptyLanguage[E](), nil)
	return &Model[E]{
		algebra: algebra,
		theory:  theory,
	}
}

func NewSet[E Element[E]](set CarrierSet[E]) (*Model[E], error) {
	if set == nil {
		return nil, errs.NewIsNil("carrier set")
	}
	algebra, err := NewAlgebra(set, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating algebra")
	}
	theory, err := NewTheory(algebra.language, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating theory")
	}
	return &Model[E]{
		algebra: algebra,
		theory:  theory,
	}, nil
}

func NewMagma[E Element[E]](set CarrierSet[E], op *BinaryOperator[E]) (*Model[E], error) {
	Set, err := NewSet(set)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating set model")
	}
	return Extend(Set).
		EnrichWithBinaryOperator(op).
		IsClosed2(op).
		Finalize(), nil
}

func NewSemiGroup[E Element[E]](set CarrierSet[E], op *BinaryOperator[E]) (*Model[E], error) {
	magma, err := NewMagma(set, op)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating magma")
	}
	return Extend(magma).
		IsAssociative(op).
		Finalize(), nil
}

func NewMonoid[E Element[E]](set CarrierSet[E], op *BinaryOperator[E], id *Constant[E]) (*Model[E], error) {
	semigroup, err := NewSemiGroup(set, op)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating semigroup")
	}
	return Extend(semigroup).
		WithIdentityElement(id, op).
		Finalize(), nil
}

func NewGroup[E Element[E]](set CarrierSet[E], op *BinaryOperator[E], id *Constant[E], inv *UnaryOperator[E]) (*Model[E], error) {
	monoid, err := NewMonoid(set, op, id)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating monoid")
	}
	return Extend(monoid).
		WithInverseOperator(inv, op).
		Finalize(), nil
}

func NewDoubleMagma[E Element[E]](set CarrierSet[E], op1, op2 *BinaryOperator[E]) (*Model[E], error) {
	magma, err := NewMagma(set, op1)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating first magma")
	}
	return Extend(magma).EnrichWithBinaryOperator(op2).Finalize(), nil
}

func NewHemiRing[E Element[E]](set CarrierSet[E], radd, rmul *BinaryOperator[E]) (*Model[E], error) {
	additiveSemiGroup, err := NewSemiGroup(set, radd)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating additive semigroup")
	}
	multiplicativeSemiGroup, err := NewSemiGroup(set, rmul)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating multiplicative semigroup")
	}
	return Amalgamate(additiveSemiGroup, multiplicativeSemiGroup).
		WithDistributiveProperty(rmul, radd).
		Finalize(), nil
}

func NewSemiRing[E Element[E]](set CarrierSet[E], radd, rmul *BinaryOperator[E], one *Constant[E]) (*Model[E], error) {
	additiveSemiGroup, err := NewSemiGroup(set, radd)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating additive semigroup")
	}
	multiplicativeMonoid, err := NewMonoid(set, rmul, one)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating multiplicative monoid")
	}
	return Amalgamate(additiveSemiGroup, multiplicativeMonoid).
		WithDistributiveProperty(rmul, radd).
		Finalize(), nil
}

func NewRig[E Element[E]](set CarrierSet[E], radd, rmul *BinaryOperator[E], zero, one *Constant[E]) (*Model[E], error) {
	additiveMonoid, err := NewMonoid(set, radd, zero)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating additive monoid")
	}
	multiplicativeMonoid, err := NewMonoid(set, rmul, one)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating multiplicative monoid")
	}
	return Amalgamate(additiveMonoid, multiplicativeMonoid).
		WithDistributiveProperty(rmul, radd).
		Finalize(), nil
}

func NewRng[E Element[E]](set CarrierSet[E], radd, rmul *BinaryOperator[E], zero *Constant[E], neg *UnaryOperator[E]) (*Model[E], error) {
	additiveGroup, err := NewGroup(set, radd, zero, neg)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating additive group")
	}
	multiplicativeSemiGroup, err := NewSemiGroup(set, rmul)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating multiplicative semigroup")
	}
	return Amalgamate(additiveGroup, multiplicativeSemiGroup).
		WithDistributiveProperty(rmul, radd).
		Finalize(), nil
}

func NewRing[E Element[E]](set CarrierSet[E], radd, rmul *BinaryOperator[E], zero, one *Constant[E], neg *UnaryOperator[E]) (*Model[E], error) {
	additiveGroup, err := NewGroup(set, radd, zero, neg)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating additive group")
	}
	multiplicativeMonoid, err := NewMonoid(set, rmul, one)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating multiplicative monoid")
	}
	return Amalgamate(additiveGroup, multiplicativeMonoid).
		WithDistributiveProperty(rmul, radd).
		Finalize(), nil
}

func NewField[E Element[E]](set CarrierSet[E], radd, rmul *BinaryOperator[E], zero, one *Constant[E], neg, inv *UnaryOperator[E]) (*Model[E], error) {
	additiveGroup, err := NewGroup(set, radd, zero, neg)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating additive group")
	}
	multiplicativeMonoid, err := NewMonoid(set, rmul, one)
	if err != nil {
		return nil, errs.WrapFailed(err, "creating multiplicative monoid")
	}
	return Amalgamate(additiveGroup, multiplicativeMonoid).
		WithDistributiveProperty(rmul, radd).
		WithInverseOperator(inv, rmul, func(x E) bool {
			return !x.Equal(zero.value)
		}).Finalize(), nil
}

// import (
// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// 	"github.com/bronlabs/bron-crypto/pkg/base/utils"
// )

// func Set[C CarrierSet[E], E Element[E]](set C) (*Theory[C, E], error) {
// 	if utils.IsNil(set) {
// 		return nil, errs.NewIsNil("carrier set")
// 	}
// 	return &Theory[C, E]{
// 		CarrierSet: set,
// 		Signature: &Signature[E]{
// 			Nullary: make(DistinguishedElements[E]),
// 			Unary:   []UnaryOperator[E]{},
// 			Binary:  []BinaryOperator[E]{},
// 		},
// 		Axiom: &Axioms[E]{
// 			Unary:   []UnaryProperty[E]{},
// 			Binary:  []BinaryProperty[E]{},
// 			Ternary: []TernaryProperty[E]{},
// 		},
// 	}, nil
// }

// func Magma[C CarrierSet[E], E Element[E]](set C, op BinaryOperator[E]) (*Theory[C, E], error) {
// 	t, err := Set(set)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating void")
// 	}
// 	t.Signature.Binary = append(t.Signature.Binary, op)
// 	t.Axiom.Binary = append(t.Axiom.Binary, op.IsClosed)
// 	return t, nil
// }

// func SemiGroup[C CarrierSet[E], E Element[E]](set C, op BinaryOperator[E]) (*Theory[C, E], error) {
// 	t, err := Magma(set, op)
// 	if err != nil {
// 		return nil, err
// 	}
// 	t.Axiom.Ternary = append(t.Axiom.Ternary, op.IsAssociative)
// 	return t, nil
// }

// func Monoid[C CarrierSet[E], E Element[E]](set C, op BinaryOperator[E], id *Constant[E]) (*Theory[C, E], error) {
// 	t, err := SemiGroup(set, op)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating semigroup")
// 	}
// 	if err := t.Signature.Nullary.Add(id); err != nil {
// 		return nil, errs.WrapFailed(err, "adding identity element")
// 	}
// 	t.Axiom.Unary = append(t.Axiom.Unary, func(x E) bool {
// 		return op.IsIdentity(id.Value, x)
// 	})
// 	return t, nil
// }

// func Group[C CarrierSet[E], E Element[E]](set C, op BinaryOperator[E], id *Constant[E], inv UnaryOperator[E]) (*Theory[C, E], error) {
// 	t, err := Monoid(set, op, id)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating monoid")
// 	}
// 	t.Signature.Unary = append(t.Signature.Unary, inv)
// 	t.Axiom.Unary = append(t.Axiom.Unary, func(x E) bool {
// 		return op.IsInverse(inv(x), id.Value, x)
// 	})
// 	return t, nil
// }

// func DoubleMagma[C CarrierSet[E], E Element[E]](set C, op1, op2 BinaryOperator[E]) (*Theory[C, E], error) {
// 	t, err := Magma(set, op1)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating magma")
// 	}
// 	t2, err := Magma(set, op2)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating second magma")
// 	}
// 	if err := t.Merge(t2); err != nil {
// 		return nil, errs.WrapFailed(err, "merging two magmas")
// 	}
// 	t.Axiom.Ternary = append(t.Axiom.Ternary, func(x, y, z E) bool {
// 		return op2.IsDistributive(op1, x, y, z)
// 	})
// 	return t, nil
// }

// func HemiRing[C CarrierSet[E], E Element[E]](set C, op1, op2 BinaryOperator[E]) (*Theory[C, E], error) {
// 	t, err := SemiGroup(set, op1)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating first semigroup")
// 	}
// 	t2, err := SemiGroup(set, op2)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating second semigroup")
// 	}
// 	if err := t.Merge(t2); err != nil {
// 		return nil, errs.WrapFailed(err, "merging two semigroups")
// 	}
// 	t.Axiom.Ternary = append(t.Axiom.Ternary, func(x, y, z E) bool {
// 		return op2.IsDistributive(op1, x, y, z)
// 	})
// 	return t, nil
// }

// func SemiRing[C CarrierSet[E], E Element[E]](set C, add, mul BinaryOperator[E], one *Constant[E]) (*Theory[C, E], error) {
// 	t, err := HemiRing(set, add, mul)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating hemi-ring")
// 	}
// 	t2, err := Monoid(set, mul, one)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating monoid")
// 	}
// 	if err := t.Merge(t2); err != nil {
// 		return nil, errs.WrapFailed(err, "merging hemi-ring and monoid")
// 	}
// 	return t, nil
// }

// func Rig[C CarrierSet[E], E Element[E]](set C, add, mul BinaryOperator[E], zero, one *Constant[E]) (*Theory[C, E], error) {
// 	t, err := SemiRing(set, add, mul, one)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating semi-ring")
// 	}
// 	t2, err := Monoid(set, add, zero)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating monoid")
// 	}
// 	if err := t.Merge(t2); err != nil {
// 		return nil, errs.WrapFailed(err, "merging semi-ring and monoid")
// 	}
// 	t.Axiom.Unary = append(t.Axiom.Unary, func(x E) bool {
// 		return mul.IsInverse(one.Value, zero.Value, x)
// 	})
// 	return t, nil
// }

// func Rng[C CarrierSet[E], E Element[E]](set C, add, mul BinaryOperator[E], zero, one *Constant[E], additiveInverse UnaryOperator[E]) (*Theory[C, E], error) {
// 	t, err := HemiRing(set, add, mul)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating hemi-ring")
// 	}
// 	t2, err := Group(set, add, zero, additiveInverse)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating group")
// 	}
// 	if err := t.Merge(t2); err != nil {
// 		return nil, errs.WrapFailed(err, "merging hemi-ring and group")
// 	}
// 	return t, nil
// }

// func Ring[C CarrierSet[E], E Element[E]](set C, add, mul BinaryOperator[E], zero, one *Constant[E], additiveInverse UnaryOperator[E]) (*Theory[C, E], error) {
// 	t, err := Rig(set, add, mul, zero, one)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating rig")
// 	}
// 	t2, err := Rng(set, add, mul, zero, one, additiveInverse)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating rng")
// 	}
// 	if err := t.Merge(t2); err != nil {
// 		return nil, errs.WrapFailed(err, "merging rig and rng")
// 	}
// 	return t, nil
// }

// func AbelianRing[C CarrierSet[E], E Element[E]](set C, add, mul BinaryOperator[E], zero, one *Constant[E], additiveInverse UnaryOperator[E]) (*Theory[C, E], error) {
// 	t, err := Ring(set, add, mul, zero, one, additiveInverse)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating ring")
// 	}
// 	if err := t.MakeAbelian(add); err != nil {
// 		return nil, errs.WrapFailed(err, "making ring abelian under addition")
// 	}
// 	if err := t.MakeAbelian(mul); err != nil {
// 		return nil, errs.WrapFailed(err, "making ring abelian under multiplication")
// 	}
// 	return t, nil
// }

// func Field[C CarrierSet[E], E Element[E]](set C, add, mul BinaryOperator[E], zero, one *Constant[E], additiveInverse, multiplicativeInverse UnaryOperator[E]) (*Theory[C, E], error) {
// 	t, err := AbelianRing(set, add, mul, zero, one, additiveInverse)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating ring")
// 	}
// 	t.Signature.Unary = append(t.Signature.Unary, RestrictUnaryOperator(multiplicativeInverse, func(x E) bool {
// 		return !x.Equal(zero.Value)
// 	}))
// 	return t, nil
// }

// func Module[M CarrierSet[ME], R CarrierSet[RE], ME Element[ME], RE Element[RE]](
// 	mset M, mop BinaryOperator[ME], mid *Constant[ME], minv UnaryOperator[ME],
// 	rset R, radd BinaryOperator[RE], rmul BinaryOperator[RE], rzero *Constant[RE], rone *Constant[RE], rneg UnaryOperator[RE],
// 	smul MixedSortedBinaryOperator[RE, ME],
// ) (*TwoSortedTheory[M, R, ME, RE], error) {
// 	if utils.IsNil(mset) || utils.IsNil(rset) {
// 		return nil, errs.NewIsNil("carrier sets")
// 	}
// 	group, err := Group(mset, mop, mid, minv)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating group")
// 	}
// 	if err := group.MakeAbelian(mop); err != nil {
// 		return nil, errs.WrapFailed(err, "making group abelian")
// 	}
// 	scalarRing, err := AbelianRing(rset, radd, rmul, rzero, rone, rneg)
// 	if err != nil {
// 		return nil, errs.WrapFailed(err, "creating scalar ring")
// 	}
// 	return &TwoSortedTheory[M, R, ME, RE]{
// 		First:  group,
// 		Second: scalarRing,
// 		MixedAxioms: &MixedAxioms[RE, ME]{
// 			Binary: []MixedSortedBinaryProperty[RE, ME]{
// 				smul.IsClosed,
// 			},
// 			Ternary: []MixedSortedTernaryProperty[RE, ME]{
// 				MixedSortedTernaryProperty[RE, ME](func(x RE, y, z ME) bool {
// 					return smul.IsLeftDistributive(mop, x, y, z)
// 				}),
// 				MixedSortedTernaryProperty[RE, ME](func(x, y RE, z ME) bool {
// 					return smul.IsRightDistributive(radd, mop, x, y, z)
// 				}),
// 			},
// 		},
// 		MixedSignature: &MixedSignature[ME, RE]{
// 			Binary: []MixedSortedBinaryOperator[ME, RE]{smul},
// 		},
// 	}, nil

// 	// Left distributivity over vector addition
// 	// right distributivity over scalar addition
// 	// mixed associativity
// 	// unit acts as identity
// 	// zeros map to module
// 	// module := NewTwoSortedTheory(group, scalarRing, mixedSignature, MixedAxioms[E1, E2]{})
// 	// return module
// }

// func VectorSpace[C1 CarrierSet[E1], C2 CarrierSet[E2], E1 Element[E1], E2 Element[E2]](
// 	mset C1, mop BinaryOperator[E1], mid E1, minv UnaryOperator[E1],
// 	fset C2, fadd BinaryOperator[E2], fmul BinaryOperator[E2], fzero E2, fone E2, fneg UnaryOperator[E2], finv UnaryOperator[E2],
// 	smul MixedSortedBinaryOperator[E1, E2],
// ) TwoSortedTheory[C1, C2, E1, E2] {
// 	group, _ := MakeAbelian(Group(mset, mop, mid, minv), mop)
// 	scalarField := Field(fset, fadd, fmul, fzero, fone, fneg, finv)

// 	mixedSignature := MixedSignature[E1, E2]{
// 		Binary: []MixedSortedBinaryOperator[E1, E2]{smul},
// 	}
// 	// Left distributivity over vector addition
// 	// right distributivity over scalar addition
// 	// mixed associativity
// 	// unit acts as identity
// 	// zeros map to module
// 	module := NewTwoSortedTheory(group, scalarField, mixedSignature, MixedAxioms[E1, E2]{})
// 	return module
// }
