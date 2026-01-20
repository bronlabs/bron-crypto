package properties

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

// ************************* Group-like.

func Set[S Structure, E Element](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	st := &Carrier[S, E]{
		Value: structure,
		Dist:  g,
	}
	return &Model[S, E]{
		Carrier: st,
		Theory:  nil,
	}
}

func Magma[S algebra.Magma[E], E algebra.MagmaElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E], op *BinaryOperator[E],
) *Model[S, E] {
	t.Helper()
	st := &Carrier[S, E]{
		Value: structure,
		Dist:  g,
	}
	return &Model[S, E]{
		Carrier: st,
		Theory: append(
			EqualityProperties(t, st, Equality[E]()),
			ClosureProperty(t, st, op),
		),
	}
}

func SemiGroup[S algebra.SemiGroup[E], E algebra.SemiGroupElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E], op *BinaryOperator[E],
) *Model[S, E] {
	t.Helper()
	magmaModel := Magma(t, structure, g, op)
	return &Model[S, E]{
		Carrier: magmaModel.Carrier,
		Theory: append(magmaModel.Theory,
			AssociativityProperty(t, magmaModel.Carrier, op),
		),
	}
}

func AdditiveSemiGroup[S algebra.AdditiveSemiGroup[E], E algebra.AdditiveSemiGroupElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	semiGroup := SemiGroup(t, structure, g, Addition[E]())
	return &Model[S, E]{
		Carrier: semiGroup.Carrier,
		Theory: append(semiGroup.Theory,
			CanDoubleProperty(t, semiGroup.Carrier),
		),
	}
}

func CyclicSemiGroup[S algebra.CyclicSemiGroup[E], E algebra.CyclicSemiGroupElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E], op *BinaryOperator[E],
) *Model[S, E] {
	t.Helper()
	semiGroup := SemiGroup(t, structure, g, op)
	return &Model[S, E]{
		Carrier: semiGroup.Carrier,
		Theory: append(semiGroup.Theory,
			CyclicProperty(t, semiGroup.Carrier, op),
		),
	}
}

func MultiplicativeSemiGroup[S algebra.MultiplicativeSemiGroup[E], E algebra.MultiplicativeSemiGroupElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	semiGroup := SemiGroup(t, structure, g, Multiplication[E]())
	return &Model[S, E]{
		Carrier: semiGroup.Carrier,
		Theory: append(semiGroup.Theory,
			CanSquareProperty(t, semiGroup.Carrier),
		),
	}
}

func Monoid[S algebra.Monoid[E], E algebra.MonoidElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E], op *BinaryOperator[E], identity *Constant[E],
) *Model[S, E] {
	t.Helper()
	semiGroup := SemiGroup(t, structure, g, op)
	return &Model[S, E]{
		Carrier: semiGroup.Carrier,
		Theory: append(semiGroup.Theory,
			IdentityProperty(t, semiGroup.Carrier, op, identity),
		),
	}
}

func AdditiveMonoid[S algebra.AdditiveMonoid[E], E algebra.AdditiveMonoidElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	monoid := Monoid(t, structure, g, Addition[E](), AdditiveIdentity(structure))
	additiveSemiGroup := AdditiveSemiGroup(t, structure, g)
	out := Union(t, monoid, additiveSemiGroup)
	out.Theory = append(monoid.Theory,
		CanDistinguishAdditiveIdentity(t, monoid.Carrier),
		CanTrySub(t, monoid.Carrier),
		CanTryNeg(t, monoid.Carrier),
	)
	return monoid
}

func MultiplicativeMonoid[S algebra.MultiplicativeMonoid[E], E algebra.MultiplicativeMonoidElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	monoid := Monoid(t, structure, g, Multiplication[E](), MultiplicativeIdentity(structure))
	multiplicativeSemiGroup := MultiplicativeSemiGroup(t, structure, g)
	out := Union(t, monoid, multiplicativeSemiGroup)
	out.Theory = append(monoid.Theory,
		CanDistinguishMultiplicativeIdentity(t, monoid.Carrier),
		CanTryDiv(t, monoid.Carrier),
		CanTryInv(t, monoid.Carrier),
	)
	return monoid
}

func CyclicMonoid[S algebra.CyclicMonoid[E], E algebra.CyclicMonoidElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E], op *BinaryOperator[E], identity *Constant[E],
) *Model[S, E] {
	t.Helper()
	monoid := Monoid(t, structure, g, op, identity)
	cyclicSemiGroup := CyclicSemiGroup(t, structure, g, op)
	return Union(t, monoid, cyclicSemiGroup)
}

func Group[S algebra.Group[E], E algebra.GroupElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E], op *BinaryOperator[E],
	identity *Constant[E], inv *UnaryOperator[E],
) *Model[S, E] {
	t.Helper()
	monoid := Monoid(t, structure, g, op, identity)
	return &Model[S, E]{
		Carrier: monoid.Carrier,
		Theory: append(monoid.Theory,
			GroupInverseProperty(t, monoid.Carrier, op, identity, inv),
		),
	}
}

func AdditiveGroup[S algebra.AdditiveGroup[E], E algebra.AdditiveGroupElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	group := Group(t, structure, g, Addition[E](), AdditiveIdentity(structure), Negation[E]())
	additiveMonoid := AdditiveMonoid(t, structure, g)
	out := Union(t, group, additiveMonoid)
	out.Theory = append(group.Theory,
		CanTrySub(t, group.Carrier),
		CanTryNeg(t, group.Carrier),
	)
	return out
}

func MultiplicativeGroup[S algebra.MultiplicativeGroup[E], E algebra.MultiplicativeGroupElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	group := Group(t, structure, g, Multiplication[E](), MultiplicativeIdentity(structure), Inversion[E]())
	multiplicativeMonoid := MultiplicativeMonoid(t, structure, g)
	out := Union(t, group, multiplicativeMonoid)
	out.Theory = append(group.Theory,
		CanTryDiv(t, group.Carrier),
		CanTryInv(t, group.Carrier),
	)
	return out
}

func CyclicGroup[S algebra.CyclicGroup[E], E algebra.CyclicGroupElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E], op *BinaryOperator[E],
	identity *Constant[E], inv *UnaryOperator[E],
) *Model[S, E] {
	t.Helper()
	group := Group(t, structure, g, op, identity, inv)
	cyclicMonoid := CyclicMonoid(t, structure, g, op, identity)
	return Union(t, group, cyclicMonoid)
}

func DoubleMagma[S algebra.DoubleMagma[E], E algebra.DoubleMagmaElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
	op1, op2 *BinaryOperator[E],
) *Model[S, E] {
	t.Helper()
	magma1 := Magma(t, structure, g, op1)
	magma2 := Magma(t, structure, g, op2)
	return Union(t, magma1, magma2)
}

func HemiRing[S algebra.HemiRing[E], E algebra.HemiRingElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	additiveSemiGroup := AdditiveSemiGroup(t, structure, g)
	multiplicativeSemiGroup := MultiplicativeSemiGroup(t, structure, g)
	out := Union(t, additiveSemiGroup, multiplicativeSemiGroup)
	out.Theory = append(out.Theory,
		HemiRingIsStandardProperty(t, out.Carrier),
		DistributivityOfMulOverAddProperty(t, out.Carrier),
	)
	return out
}

func SemiRing[S algebra.SemiRing[E], E algebra.SemiRingElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	hemiRing := HemiRing(t, structure, g)
	multiplicativeMonoid := MultiplicativeMonoid(t, structure, g)
	out := Union(t, hemiRing, multiplicativeMonoid)
	return out
}

func Rig[S algebra.Rig[E], E algebra.RigElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	semiRing := SemiRing(t, structure, g)
	additiveMonoid := AdditiveMonoid(t, structure, g)
	out := Union(t, semiRing, additiveMonoid)
	return out
}

func EuclideanSemiDomain[S algebra.EuclideanSemiDomain[E], E algebra.EuclideanSemiDomainElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	ring := Rig(t, structure, g)
	out := &Model[S, E]{
		Carrier: ring.Carrier,
		Theory: append(ring.Theory,
			EuclideanDivisionProperty(t, ring.Carrier),
		),
	}
	return out
}

func Rng[S algebra.Rng[E], E algebra.RngElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	hemiRing := HemiRing(t, structure, g)
	additiveGroup := AdditiveGroup(t, structure, g)
	out := Union(t, hemiRing, additiveGroup)
	return out
}

func Ring[S algebra.Ring[E], E algebra.RingElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	rng := Rng(t, structure, g)
	rig := Rig(t, structure, g)
	out := Union(t, rng, rig)
	return out
}

func EuclideanDomain[S algebra.EuclideanDomain[E], E algebra.EuclideanDomainElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	ring := Ring(t, structure, g)
	euclideanSemiDomain := EuclideanSemiDomain(t, structure, g)
	return Union(t, ring, euclideanSemiDomain)
}

func Field[S algebra.Field[E], E algebra.FieldElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	require.Positive(t, structure.ExtensionDegree())
	require.False(t, structure.Zero().Equal(structure.One())) // Requirement to rule out trivial rings.
	out := EuclideanDomain(t, structure, g)
	out.Theory = append(out.Theory,
		EveryNonZeroElementHasMultiplicativeInverseProperty(t, out.Carrier),
		CommutativityProperty(t, out.Carrier, Addition[E]()),
		CommutativityProperty(t, out.Carrier, Multiplication[E]()),
	)
	return out
}

func FieldExtension[S algebra.FieldExtension[E], E algebra.FieldExtensionElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	out := Field(t, structure, g)
	out.Theory = append(out.Theory,
		FieldExtensionComponentBytesRoundTripProperty(t, out.Carrier),
	)
	return out
}

func FiniteField[S algebra.FiniteField[E], E algebra.FiniteFieldElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	return Field(t, structure, g)
}

func SemiModule[S algebra.SemiModule[E, RE], R algebra.SemiRing[RE], E algebra.SemiModuleElement[E, RE], RE algebra.SemiRingElement[RE]](
	t *testing.T, structure S, scalarRing R, g *rapid.Generator[E], gb *rapid.Generator[RE],
	op *BinaryOperator[E], identity *Constant[E],
	scalarOp *Action[RE, E],
) *TwoSortedModel[S, R, E, RE] {
	t.Helper()
	monoid := Monoid(t, structure, g, op, identity)
	baseSemiRing := SemiRing(t, scalarRing, gb)
	out := PairWithAction(t, monoid, baseSemiRing, scalarOp)
	out.Theory = append(out.Theory,
		CommutativityProperty(t, out.First, op),
		CommutativityProperty(t, out.Second, Addition[RE]()),
		CommutativityProperty(t, out.Second, Multiplication[RE]()),
		LeftDistributivityOfActionOverSemiModuleOperationProperty(t, out.Carrier2),
		RightDistributivityOfSemiModuleOperationOverBaseSemiRingAdditionProperty(t, out.Carrier2),
		AssociativityOfScalarsWRTRingMultiplicationProperty(t, out.Carrier2),
	)
	return out
}

func AdditiveSemiModule[S algebra.AdditiveSemiModule[E, RE], R algebra.SemiRing[RE], E algebra.AdditiveSemiModuleElement[E, RE], RE algebra.SemiRingElement[RE]](
	t *testing.T, structure S, scalarRing R, g *rapid.Generator[E], gb *rapid.Generator[RE],
) *TwoSortedModel[S, R, E, RE] {
	t.Helper()
	semiModule := SemiModule(t, structure, scalarRing, g, gb, Addition[E](), AdditiveIdentity(structure), ScalarMultiplication[E]())
	additiveMonoid := AdditiveMonoid(t, structure, g)
	out := UnionAlongFirst(t, semiModule, additiveMonoid)
	out.Theory = append(out.Theory,
		ScalarOpIsScalarMultiplicationProperty(t, out.Carrier2),
	)
	return out
}

func MultiplicativeSemiModule[S algebra.MultiplicativeSemiModule[E, RE], R algebra.SemiRing[RE], E algebra.MultiplicativeSemiModuleElement[E, RE], RE algebra.SemiRingElement[RE]](
	t *testing.T, structure S, scalarRing R, g *rapid.Generator[E], gb *rapid.Generator[RE],
) *TwoSortedModel[S, R, E, RE] {
	t.Helper()
	semiModule := SemiModule(t, structure, scalarRing, g, gb, Multiplication[E](), MultiplicativeIdentity(structure), ScalarExponentiation[E]())
	multiplicativeMonoid := MultiplicativeMonoid(t, structure, g)
	out := UnionAlongFirst(t, semiModule, multiplicativeMonoid)
	out.Theory = append(out.Theory,
		ScalarOpIsScalarExponentiationProperty(t, out.Carrier2),
	)
	return out
}

func Module[S algebra.Module[E, RE], R algebra.Ring[RE], E algebra.ModuleElement[E, RE], RE algebra.RingElement[RE]](
	t *testing.T, structure S, scalarRing R, g *rapid.Generator[E], gb *rapid.Generator[RE],
	op *BinaryOperator[E], identity *Constant[E], inv *UnaryOperator[E],
	scalarOp *Action[RE, E],
) *TwoSortedModel[S, R, E, RE] {
	t.Helper()
	semiModule := SemiModule(t, structure, scalarRing, g, gb, op, identity, scalarOp)
	group := Group(t, structure, g, op, identity, inv)
	out := UnionAlongFirst(t, semiModule, group)
	out.Theory = append(out.Theory,
		BaseRingIdentityActsAsModuleIdentityProperty(t, out.Carrier2),
	)
	return out
}

func AdditiveModule[S algebra.AdditiveModule[E, RE], R algebra.Ring[RE], E algebra.AdditiveModuleElement[E, RE], RE algebra.RingElement[RE]](
	t *testing.T, structure S, scalarRing R, g *rapid.Generator[E], gb *rapid.Generator[RE],
) *TwoSortedModel[S, R, E, RE] {
	t.Helper()
	module := Module(t, structure, scalarRing, g, gb, Addition[E](), AdditiveIdentity(structure), Negation[E](), ScalarMultiplication[E]())
	additiveSemiModule := AdditiveSemiModule(t, structure, scalarRing, g, gb)
	additiveGroup := AdditiveGroup(t, structure, g)
	out := UnionAlongFirst(t, Union2(t, module, additiveSemiModule), additiveGroup)
	out.Theory = append(out.Theory,
		ScalarOpIsScalarMultiplicationProperty(t, out.Carrier2),
	)
	return out
}

func MultiplicativeModule[S algebra.MultiplicativeModule[E, RE], R algebra.Ring[RE], E algebra.MultiplicativeModuleElement[E, RE], RE algebra.RingElement[RE]](
	t *testing.T, structure S, scalarRing R, g *rapid.Generator[E], gb *rapid.Generator[RE],
) *TwoSortedModel[S, R, E, RE] {
	t.Helper()
	module := Module(t, structure, scalarRing, g, gb, Multiplication[E](), MultiplicativeIdentity(structure), Inversion[E](), ScalarExponentiation[E]())
	multiplicativeSemiModule := MultiplicativeSemiModule(t, structure, scalarRing, g, gb)
	multiplicativeGroup := MultiplicativeGroup(t, structure, g)
	out := UnionAlongFirst(t, Union2(t, module, multiplicativeSemiModule), multiplicativeGroup)
	out.Theory = append(out.Theory,
		ScalarOpIsScalarExponentiationProperty(t, out.Carrier2),
	)
	return out
}

func VectorSpace[
	S algebra.VectorSpace[E, FE], F algebra.Field[FE],
	E algebra.Vector[E, FE], FE algebra.FieldElement[FE],
](
	t *testing.T, structure S, scalarField F, g *rapid.Generator[E], gb *rapid.Generator[FE],
	op *BinaryOperator[E], identity *Constant[E], inv *UnaryOperator[E],
	scalarOp *Action[FE, E],
) *TwoSortedModel[S, F, E, FE] {
	t.Helper()
	module := Module(t, structure, scalarField, g, gb, op, identity, inv, scalarOp)
	field := Field(t, scalarField, gb)
	return UnionAlongSecond(t, module, field)
}

func Algebra[S algebra.Algebra[AE, RE], R algebra.Ring[RE], AE algebra.AlgebraElement[AE, RE], RE algebra.RingElement[RE]](
	t *testing.T, structure S, scalarRing R, g *rapid.Generator[AE], gb *rapid.Generator[RE],
) *TwoSortedModel[S, R, AE, RE] {
	t.Helper()
	module := AdditiveModule(t, structure, scalarRing, g, gb)
	ring := Ring(t, structure, g)
	out := UnionAlongFirst(t, module, ring)
	return out
}

func PolynomialRing[
	PS algebra.PolynomialRing[P, S], SS algebra.Ring[S],
	P algebra.Polynomial[P, S], S algebra.RingElement[S],
](
	t *testing.T, structure PS, coeffRing SS, g *rapid.Generator[P], gb *rapid.Generator[S],
) *TwoSortedModel[PS, SS, P, S] {
	t.Helper()
	alg := Algebra(t, structure, coeffRing, g, gb)
	euclideanDomain := EuclideanDomain(t, structure, g)
	out := UnionAlongFirst(t, alg, euclideanDomain)
	out.Theory = append(out.Theory,
		PolynomialLikeConstantTermProperty[PS, SS, SS](t, out.First),
		PolynomialLikeIsConstantProperty[PS, SS, SS](t, out.First),
		PolynomialLikeDegreeProperty[PS, SS, SS](t, out.First),
		PolynomialLikeDerivativeDegreeDeclinesProperty[PS, SS, SS](t, out.First),
		PolynomialLikeDerivativeOfConstantIsZeroProperty[PS, SS, SS](t, out.First),
		UnivariatePolynomialLikeFromCoefficientsRoundTripProperty(t, out.First),
		PolynomialLeadingCoefficientProperty(t, out.First),
		PolynomialEvalAtZeroProperty(t, out.First, coeffRing),
		PolynomialEvalConstantProperty(t, out.First, gb),
	)
	return out
}

func PolynomialModule[
	PM algebra.PolynomialModule[MP, P, C, S],
	CS algebra.Module[C, S],
	SS algebra.Ring[S],
	MP algebra.ModuleValuedPolynomial[MP, P, C, S],
	P algebra.Polynomial[P, S],
	C algebra.ModuleElement[C, S],
	S algebra.RingElement[S],
](
	t *testing.T, structure PM, scalars SS, g *rapid.Generator[MP], gs *rapid.Generator[S],
	op *BinaryOperator[MP], identity *Constant[MP], inv *UnaryOperator[MP],
	scalarOp *Action[S, MP],
) *TwoSortedModel[PM, SS, MP, S] {
	t.Helper()
	module := Module(t, structure, scalars, g, gs, op, identity, inv, scalarOp)
	module.Theory = append(module.Theory,
		PolynomialLikeConstantTermProperty[PM, SS, CS](t, module.First),
		PolynomialLikeIsConstantProperty[PM, SS, CS](t, module.First),
		PolynomialLikeDegreeProperty[PM, SS, CS](t, module.First),
		PolynomialLikeDerivativeDegreeDeclinesProperty[PM, SS, CS](t, module.First),
		PolynomialLikeDerivativeOfConstantIsZeroProperty[PM, SS, CS](t, module.First),
	)
	return module
}

func NumericStructure[S interface {
	Structure
	algebra.NumericStructure[E]
}, E interface {
	algebra.Numeric
	base.Equatable[E]
}](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	out := Set(t, structure, g)
	out.Theory = append(out.Theory,
		NumericStructureFromBytesBERoundTripProperty(t, out.Carrier),
	)
	return out
}

func NPlusLike[S algebra.NPlusLike[E], E algebra.NatPlusLike[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	numericStructure := NumericStructure(t, structure, g)
	out := &Model[S, E]{
		Carrier: numericStructure.Carrier,
		Theory: append(numericStructure.Theory,
			FromCardinalRoundTripProperty(t, numericStructure.Carrier),
			AnyNumberIsEitherOddOrEvenProperty(t, numericStructure.Carrier),
		),
	}
	return out
}

func NLike[S algebra.NLike[E], E algebra.NatLike[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	nPlusLike := NPlusLike(t, structure, g)
	euclideanSemiDomain := EuclideanSemiDomain(t, structure, g)
	out := Union(t, nPlusLike, euclideanSemiDomain)
	out.Theory = append(nPlusLike.Theory,
		AnyNaturalNumberIsEitherZeroOrPositiveProperty(t, out.Carrier),
	)
	return out
}

func ZLike[S algebra.ZLike[E], E algebra.IntLike[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	out := EuclideanDomain(t, structure, g)
	out.Theory = append(out.Theory,
		AnyNumberIsEitherOddOrEvenProperty(t, out.Carrier),
		AnyIntegerIsEitherPositiveOrNegativeOrZero(t, out.Carrier),
	)
	return out
}

func ZModLike[S algebra.ZModLike[E], E algebra.UintLike[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	nLike := NLike(t, structure, g)
	ring := Ring(t, structure, g)
	out := Union(t, ring, nLike)
	out.Theory = append(out.Theory,
		ZModFromBytesBEReduceRoundTripProperty(t, out.Carrier),
	)
	return out
}

func PrimeField[S algebra.PrimeField[E], E algebra.PrimeFieldElement[E]](
	t *testing.T, structure S, g *rapid.Generator[E],
) *Model[S, E] {
	t.Helper()
	require.Greater(t, structure.BitLen(), 1)
	require.True(t, structure.Characteristic().IsProbablyPrime())
	field := Field(t, structure, g)
	zModLike := ZModLike(t, structure, g)
	out := Union(t, field, zModLike)
	out.Theory = append(field.Theory,
		FromWideBytesRoundTripProperty(t, out.Carrier),
	)
	return out
}

func AbelianGroup[S algebra.AbelianGroup[E, RE], R algebra.Ring[RE], E algebra.AbelianGroupElement[E, RE], RE algebra.RingElement[RE]](
	t *testing.T, structure S, scalarRing R, g *rapid.Generator[E], gb *rapid.Generator[RE],
	op *BinaryOperator[E], identity *Constant[E], inv *UnaryOperator[E],
	scalarOp *Action[RE, E],
) *TwoSortedModel[S, R, E, RE] {
	t.Helper()
	return Module(t, structure, scalarRing, g, gb, op, identity, inv, scalarOp)
}

func PrimeGroup[
	S algebra.PrimeGroup[E, FE], F algebra.PrimeField[FE],
	E algebra.PrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE],
](
	t *testing.T, structure S, scalarField F, g *rapid.Generator[E], gb *rapid.Generator[FE],
	op *BinaryOperator[E], scalarOp *Action[FE, E],
	identity *Constant[E], inv *UnaryOperator[E],
) *TwoSortedModel[S, F, E, FE] {
	t.Helper()
	abelianGroup := AbelianGroup(t, structure, scalarField, g, gb, op, identity, inv, scalarOp)
	vectorSpace := VectorSpace(t, structure, scalarField, g, gb, op, identity, inv, scalarOp)
	cyclicSemiGroup := CyclicSemiGroup(t, structure, g, op)
	primeField := PrimeField(t, scalarField, gb)
	out := UnionAlongSecond(
		t,
		UnionAlongFirst(
			t,
			Union2(t, abelianGroup, vectorSpace),
			cyclicSemiGroup,
		),
		primeField,
	)
	out.Theory = append(out.Theory,
		CanScalarBaseOp(t, out.Carrier2),
	)
	require.True(t, out.First.Value.Order().Equal(out.Second.Value.Characteristic()), "prime group order must match base field characteristic")
	return out
}

func AdditivePrimeGroup[
	S algebra.AdditivePrimeGroup[E, FE], F algebra.PrimeField[FE],
	E algebra.AdditivePrimeGroupElement[E, FE], FE algebra.PrimeFieldElement[FE],
](
	t *testing.T, structure S, scalarField F, g *rapid.Generator[E], gb *rapid.Generator[FE],
) *TwoSortedModel[S, F, E, FE] {
	t.Helper()
	out := PrimeGroup(t, structure, scalarField, g, gb, Addition[E](), ScalarMultiplication[E](), AdditiveIdentity(structure), Negation[E]())
	out.Theory = append(out.Theory,
		CanScalarBaseMul(t, out.Carrier2),
	)
	return out
}
