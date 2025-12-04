package properties2

import (
	"slices"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

type Action[S algebra.Element[S], E algebra.Element[E]] func(S, E) E

type UnaryOperator[E algebra.Element[E]] struct {
	Func         func(E) E
	IsInvolutive bool
}

type BinaryOperator[E algebra.Element[E]] struct {
	Func          func(E, E) E
	IsCommutative bool
	IsAssociative bool
}

type Structure[S algebra.Structure[E], E algebra.Element[E]] struct {
	Carrier   S
	Generator *rapid.Generator[E]
	Constants []E
	Unary     []*UnaryOperator[E]
	Ops       []*BinaryOperator[E]
}

type TwoSortedStructure[
	S1 algebra.Structure[E1], S2 algebra.Structure[E2],
	E1 algebra.Element[E1], E2 algebra.Element[E2],
] struct {
	First      *Structure[S1, E1]
	Second     *Structure[S2, E2]
	ActionFunc Action[E2, E1]
}

// ******************** Group-like.

func MagmaStructure[S algebra.Magma[E], E algebra.MagmaElement[E]](t *testing.T, gt *rapid.Generator[E], carrier S, op *BinaryOperator[E]) *Structure[S, E] {
	t.Helper()
	return &Structure[S, E]{
		Carrier:   carrier,
		Generator: gt,
		Ops:       []*BinaryOperator[E]{op},
	}
}

func (s *Structure[S, E]) IsMagmaUnder(op *BinaryOperator[E]) bool {
	return slices.Contains(s.Ops, op)
}

func (s *Structure[S, E]) IsMagma() bool {
	return slices.ContainsFunc(s.Ops, s.IsMagmaUnder)
}

func SemiGroupStructure[S algebra.SemiGroup[E], E algebra.SemiGroupElement[E]](t *testing.T, gt *rapid.Generator[E], carrier S, op *BinaryOperator[E]) *Structure[S, E] {
	t.Helper()
	op.IsAssociative = true
	return &Structure[S, E]{
		Carrier:   carrier,
		Generator: gt,
		Ops:       []*BinaryOperator[E]{op},
	}
}

func (s *Structure[S, E]) IsSemiGroupUnder(op *BinaryOperator[E]) bool {
	return s.IsMagmaUnder(op) && op.IsAssociative
}

func (s *Structure[S, E]) IsSemiGroup() bool {
	return slices.ContainsFunc(s.Ops, s.IsSemiGroupUnder)
}

func MonoidStructure[S algebra.Monoid[E], E algebra.MonoidElement[E]](
	t *testing.T, gt *rapid.Generator[E], carrier S, op *BinaryOperator[E], identity E,
) *Structure[S, E] {
	t.Helper()
	op.IsAssociative = true
	return &Structure[S, E]{
		Carrier:   carrier,
		Generator: gt,
		Constants: []E{identity},
		Ops:       []*BinaryOperator[E]{op},
	}
}

func (s *Structure[S, E]) IsMonoidUnder(op *BinaryOperator[E], identity E) bool {
	return s.IsSemiGroupUnder(op) && slices.ContainsFunc(s.Constants, func(c E) bool { return c.Equal(identity) })
}

func (s *Structure[S, E]) IsMonoid() bool {
	for _, op := range s.Ops {
		for _, c := range s.Constants {
			if s.IsMonoidUnder(op, c) {
				return true
			}
		}
	}
	return false
}

func GroupStructure[S algebra.Group[E], E algebra.GroupElement[E]](
	t *testing.T, gt *rapid.Generator[E], carrier S, op *BinaryOperator[E], identity E, inv *UnaryOperator[E],
) *Structure[S, E] {
	t.Helper()
	op.IsAssociative = true
	inv.IsInvolutive = true
	return &Structure[S, E]{
		Carrier:   carrier,
		Generator: gt,
		Constants: []E{identity},
		Unary:     []*UnaryOperator[E]{inv},
		Ops:       []*BinaryOperator[E]{op},
	}
}

func (s *Structure[S, E]) IsGroupUnder(op *BinaryOperator[E], identity E, inv *UnaryOperator[E]) bool {
	return s.IsMonoidUnder(op, identity) && slices.ContainsFunc(s.Unary, func(u *UnaryOperator[E]) bool { return u == inv && u.IsInvolutive })
}

func (s *Structure[S, E]) IsGroup() bool {
	for _, op := range s.Ops {
		for _, c := range s.Constants {
			for _, u := range s.Unary {
				if s.IsGroupUnder(op, c, u) {
					return true
				}
			}
		}
	}
	return false
}

// ******************** Ring-like.

func DoubleMagmaStructure[S algebra.DoubleMagma[E], E algebra.DoubleMagmaElement[E]](
	t *testing.T, gt *rapid.Generator[E], carrier S, op1, op2 *BinaryOperator[E],
) *Structure[S, E] {
	t.Helper()
	return &Structure[S, E]{
		Carrier:   carrier,
		Generator: gt,
		Ops:       []*BinaryOperator[E]{op1, op2},
	}
}

func (s *Structure[S, E]) IsDoubleMagmaUnder(op1, op2 *BinaryOperator[E]) bool {
	return s.IsMagmaUnder(op1) && s.IsMagmaUnder(op2)
}

func (s *Structure[S, E]) IsDoubleMagma() bool {
	for i := range len(s.Ops) {
		for j := range len(s.Ops) {
			if i != j && s.IsDoubleMagmaUnder(s.Ops[i], s.Ops[j]) {
				return true
			}
		}
	}
	return false
}

func HemiRingStructure[S algebra.HemiRing[E], E algebra.HemiRingElement[E]](
	t *testing.T, gt *rapid.Generator[E], carrier S, addOp, mulOp *BinaryOperator[E],
) *Structure[S, E] {
	t.Helper()
	addOp.IsAssociative = true
	mulOp.IsAssociative = true
	return &Structure[S, E]{
		Carrier:   carrier,
		Generator: gt,
		Ops:       []*BinaryOperator[E]{addOp, mulOp},
	}
}

func (s *Structure[S, E]) IsHemiRingUnder(addOp, mulOp *BinaryOperator[E]) bool {
	return s.IsSemiGroupUnder(addOp) && s.IsSemiGroupUnder(mulOp)
}

func (s *Structure[S, E]) IsHemiRing() bool {
	for i := range len(s.Ops) {
		for j := range len(s.Ops) {
			if i != j && s.IsHemiRingUnder(s.Ops[i], s.Ops[j]) {
				return true
			}
		}
	}
	return false
}

func SemiRingStructure[S algebra.SemiRing[E], E algebra.SemiRingElement[E]](
	t *testing.T, gt *rapid.Generator[E], carrier S, addOp, mulOp *BinaryOperator[E], mulIdentity E,
) *Structure[S, E] {
	t.Helper()
	addOp.IsAssociative = true
	mulOp.IsAssociative = true
	return &Structure[S, E]{
		Carrier:   carrier,
		Generator: gt,
		Constants: []E{mulIdentity},
		Ops:       []*BinaryOperator[E]{addOp, mulOp},
	}
}

func (s *Structure[S, E]) IsSemiRingUnder(addOp, mulOp *BinaryOperator[E], mulIdentity E) bool {
	return s.IsHemiRingUnder(addOp, mulOp) && s.IsMonoidUnder(mulOp, mulIdentity)
}

func (s *Structure[S, E]) IsSemiRing() bool {
	for i := range len(s.Ops) {
		for j := range len(s.Ops) {
			if i != j {
				for _, c := range s.Constants {
					if s.IsSemiRingUnder(s.Ops[i], s.Ops[j], c) {
						return true
					}
				}
			}
		}
	}
	return false
}

func RigStructure[S algebra.Rig[E], E algebra.RigElement[E]](
	t *testing.T, gt *rapid.Generator[E], carrier S, addOp, mulOp *BinaryOperator[E], addIdentity, mulIdentity E,
) *Structure[S, E] {
	t.Helper()
	addOp.IsAssociative = true
	mulOp.IsAssociative = true
	return &Structure[S, E]{
		Carrier:   carrier,
		Generator: gt,
		Constants: []E{addIdentity, mulIdentity},
		Ops:       []*BinaryOperator[E]{addOp, mulOp},
	}
}

func (s *Structure[S, E]) IsRigUnder(addOp, mulOp *BinaryOperator[E], addIdentity, mulIdentity E) bool {
	return s.IsSemiRingUnder(addOp, mulOp, mulIdentity) && s.IsMonoidUnder(addOp, addIdentity)
}

func (s *Structure[S, E]) IsRig() bool {
	for i := range len(s.Ops) {
		for j := range len(s.Ops) {
			if i != j {
				for _, c1 := range s.Constants {
					for _, c2 := range s.Constants {
						if s.IsRigUnder(s.Ops[i], s.Ops[j], c1, c2) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func EuclideanSemiDomainStructure[S algebra.EuclideanSemiDomain[E], E algebra.EuclideanSemiDomainElement[E]](
	t *testing.T, gt *rapid.Generator[E], carrier S, addOp, mulOp *BinaryOperator[E], addIdentity, mulIdentity E,
) *Structure[S, E] {
	t.Helper()
	return RigStructure(t, gt, carrier, addOp, mulOp, addIdentity, mulIdentity)
}

func (s *Structure[S, E]) IsEuclideanSemiDomainUnder(addOp, mulOp *BinaryOperator[E], addIdentity, mulIdentity E) bool {
	return s.IsRigUnder(addOp, mulOp, addIdentity, mulIdentity)
}

func (s *Structure[S, E]) IsEuclideanSemiDomain() bool {
	return s.IsRig()
}

func RngStructure[S algebra.Rng[E], E algebra.RngElement[E]](
	t *testing.T, gt *rapid.Generator[E], carrier S, addOp, mulOp *BinaryOperator[E], addIdentity, mulIdentity E, addInv *UnaryOperator[E],
) *Structure[S, E] {
	t.Helper()
	addOp.IsAssociative = true
	mulOp.IsAssociative = true
	addInv.IsInvolutive = true
	return &Structure[S, E]{
		Carrier:   carrier,
		Generator: gt,
		Constants: []E{addIdentity, mulIdentity},
		Unary:     []*UnaryOperator[E]{addInv},
		Ops:       []*BinaryOperator[E]{addOp, mulOp},
	}
}

func (s *Structure[S, E]) IsRngUnder(addOp, mulOp *BinaryOperator[E], addIdentity, mulIdentity E, addInv *UnaryOperator[E]) bool {
	return s.IsRigUnder(addOp, mulOp, addIdentity, mulIdentity) && s.IsGroupUnder(addOp, addIdentity, addInv)
}

func (s *Structure[S, E]) IsRng() bool {
	for i := range len(s.Ops) {
		for j := range len(s.Ops) {
			if i != j {
				for _, c1 := range s.Constants {
					for _, c2 := range s.Constants {
						for _, u := range s.Unary {
							if s.IsRngUnder(s.Ops[i], s.Ops[j], c1, c2, u) {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

func RingStructure[S algebra.Ring[E], E algebra.RingElement[E]](
	t *testing.T, gt *rapid.Generator[E], carrier S, addOp, mulOp *BinaryOperator[E], addIdentity, mulIdentity E, addInv *UnaryOperator[E],
) *Structure[S, E] {
	t.Helper()
	addOp.IsAssociative = true
	mulOp.IsAssociative = true
	addInv.IsInvolutive = true
	return &Structure[S, E]{
		Carrier:   carrier,
		Generator: gt,
		Constants: []E{addIdentity, mulIdentity},
		Unary:     []*UnaryOperator[E]{addInv},
		Ops:       []*BinaryOperator[E]{addOp, mulOp},
	}
}

func (s *Structure[S, E]) IsRingUnder(addOp, mulOp *BinaryOperator[E], addIdentity, mulIdentity E, addInv *UnaryOperator[E]) bool {
	return s.IsRigUnder(addOp, mulOp, addIdentity, mulIdentity) && s.IsRngUnder(addOp, mulOp, addIdentity, mulIdentity, addInv)
}

func (s *Structure[S, E]) IsRing() bool {
	for i := range len(s.Ops) {
		for j := range len(s.Ops) {
			if i != j {
				for _, c1 := range s.Constants {
					for _, c2 := range s.Constants {
						for _, u := range s.Unary {
							if s.IsRingUnder(s.Ops[i], s.Ops[j], c1, c2, u) {
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

func EuclideanDomainStructure[S algebra.EuclideanDomain[E], E algebra.EuclideanDomainElement[E]](
	t *testing.T, gt *rapid.Generator[E], carrier S, addOp, mulOp *BinaryOperator[E], addIdentity, mulIdentity E, addInv *UnaryOperator[E],
) *Structure[S, E] {
	t.Helper()
	return RingStructure(t, gt, carrier, addOp, mulOp, addIdentity, mulIdentity, addInv)
}

func (s *Structure[S, E]) IsEuclideanDomainUnder(addOp, mulOp *BinaryOperator[E], addIdentity, mulIdentity E, addInv *UnaryOperator[E]) bool {
	return s.IsRingUnder(addOp, mulOp, addIdentity, mulIdentity, addInv)
}

func (s *Structure[S, E]) IsEuclideanDomain() bool {
	return s.IsRing()
}

func FieldStructure[S algebra.Field[E], E algebra.FieldElement[E]](
	t *testing.T, gt *rapid.Generator[E], carrier S, addOp, mulOp *BinaryOperator[E], addIdentity, mulIdentity E, addInv, mulInv *UnaryOperator[E],
) *Structure[S, E] {
	t.Helper()
	addOp.IsAssociative = true
	mulOp.IsAssociative = true
	addInv.IsInvolutive = true
	mulInv.IsInvolutive = true
	return &Structure[S, E]{
		Carrier:   carrier,
		Generator: gt,
		Constants: []E{addIdentity, mulIdentity},
		Unary:     []*UnaryOperator[E]{addInv, mulInv},
		Ops:       []*BinaryOperator[E]{addOp, mulOp},
	}
}

func (s *Structure[S, E]) IsFieldUnder(addOp, mulOp *BinaryOperator[E], addIdentity, mulIdentity E, addInv, mulInv *UnaryOperator[E]) bool {
	return s.IsEuclideanDomainUnder(addOp, mulOp, addIdentity, mulIdentity, addInv) // multiplicative structure of field is not cleanly defined in UA due to the zero element.
}

func (s *Structure[S, E]) IsField() bool {
	return s.IsEuclideanDomain()
}

func FieldExtensionStructure[S algebra.FieldExtension[E], E algebra.FieldExtensionElement[E]](
	t *testing.T, gt *rapid.Generator[E], carrier S, addOp, mulOp *BinaryOperator[E], addIdentity, mulIdentity E, addInv, mulInv *UnaryOperator[E],
) *Structure[S, E] {
	return FieldStructure(t, gt, carrier, addOp, mulOp, addIdentity, mulIdentity, addInv, mulInv)
}

func (s *Structure[S, E]) IsFieldExtensionUnder(addOp, mulOp *BinaryOperator[E], addIdentity, mulIdentity E, addInv, mulInv *UnaryOperator[E]) bool {
	return s.IsFieldUnder(addOp, mulOp, addIdentity, mulIdentity, addInv, mulInv)
}

func (s *Structure[S, E]) IsFieldExtension() bool {
	return s.IsField()
}

// ******************** Module-like.

func SemiModuleStructure[SM algebra.SemiModule[E, S], SR algebra.SemiRing[S], E algebra.SemiModuleElement[E, S], S algebra.SemiRingElement[S]](
	t *testing.T, monoid *Structure[SM, E], baseSemiRing *Structure[SR, S], action Action[S, E],
) *TwoSortedStructure[SM, SR, E, S] {
	t.Helper()
	require.True(t, monoid.IsMonoid(), "first structure must be a monoid")
	require.True(t, baseSemiRing.IsSemiRing(), "second structure must be a semi-ring")
	return &TwoSortedStructure[SM, SR, E, S]{
		First:      monoid,
		Second:     baseSemiRing,
		ActionFunc: action,
	}
}

func (s *TwoSortedStructure[SM, SR, E, S]) IsSemiModule() bool {
	return s.First.IsMonoid() && s.Second.IsSemiRing()
}

func ModuleStructure[M algebra.Module[E, S], R algebra.Ring[S], E algebra.ModuleElement[E, S], S algebra.RingElement[S]](
	t *testing.T, group *Structure[M, E], baseRing *Structure[R, S], action Action[S, E],
) *TwoSortedStructure[M, R, E, S] {
	t.Helper()
	require.True(t, group.IsGroup(), "first structure must be an abelian group")
	require.True(t, baseRing.IsRing(), "second structure must be a ring")
	group.Ops[0].IsCommutative = true
	return &TwoSortedStructure[M, R, E, S]{
		First:      group,
		Second:     baseRing,
		ActionFunc: action,
	}
}

func (s *TwoSortedStructure[M, R, E, S]) IsModule() bool {
	return s.First.IsGroup() && s.Second.IsRing()
}

func VectorSpaceStructure[VS algebra.VectorSpace[V, S], F algebra.Field[S], V algebra.Vector[V, S], S algebra.FieldElement[S]](
	t *testing.T, group *Structure[VS, V], baseField *Structure[F, S], action Action[S, V],
) *TwoSortedStructure[VS, F, V, S] {
	t.Helper()
	require.True(t, group.IsGroup(), "first structure must be an abelian group")
	require.True(t, baseField.IsField(), "second structure must be a field")
	group.Ops[0].IsCommutative = true
	return &TwoSortedStructure[VS, F, V, S]{
		First:      group,
		Second:     baseField,
		ActionFunc: action,
	}
}

func (s *TwoSortedStructure[VS, F, V, S]) IsVectorSpace() bool {
	return s.First.IsGroup() && s.Second.IsField()
}
