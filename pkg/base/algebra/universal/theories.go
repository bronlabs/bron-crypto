package universal

import (
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

func NewSingleSortedTheory(signature *Signature, clauses ...*HornClause) (*Theory, error) {
	if signature == nil {
		return nil, errs.NewIsNil("signature cannot be nil")
	}
	for _, clause := range clauses {
		for lit := range clause.premise.Iter() {
			if lit.atom.Sort() != signature.Sort() {
				return nil, errs.NewFailed("clause premise has sort %s, expected %s", lit.atom.Sort(), signature.Sort())
			}
		}
		if clause.conclusion.atom.Sort() != signature.Sort() {
			return nil, errs.NewFailed("clause conclusion has sort %s, expected %s", clause.conclusion.atom.Sort(), signature.Sort())
		}
	}
	if signature.Sort() == EmptySymbol && len(clauses) > 0 {
		return nil, errs.NewFailed("empty sort cannot have clauses")
	}
	lifted, err := NewMultiSortedSignature(
		map[Sort]*Signature{signature.Sort(): signature},
		nil, nil,
	)
	if err != nil {
		return nil, err
	}
	return &Theory{
		signature: lifted,
		clauses:   hashset.NewHashable(clauses...),
	}, nil
}

func NewMultiSortedTheory(signature *MultiSortedSignature, clauses ...*HornClause) (*Theory, error) {
	if signature == nil {
		return nil, errs.NewIsNil("signature cannot be nil")
	}
	return &Theory{
		signature: signature,
		clauses:   hashset.NewHashable(clauses...),
	}, nil
}

type Theory struct {
	signature *MultiSortedSignature
	clauses   ds.MutableSet[*HornClause]
	ground    ds.MutableSet[*Literal] // conjunctive ground literals
}

func (th *Theory) Signature() *MultiSortedSignature {
	return th.signature
}

func (th *Theory) Clauses() ds.Set[*HornClause] {
	return th.clauses.Freeze()
}

func (th *Theory) Ground() ds.Set[*Literal] {
	return th.ground.Freeze()
}

func (th *Theory) Sorts() ds.Set[Sort] {
	return th.signature.Sorts()
}

func (th *Theory) Clone() *Theory {
	if th == nil {
		return nil
	}
	return &Theory{
		signature: th.signature.Clone(),
		clauses:   th.clauses.Clone(),
		ground:    th.ground.Clone(),
	}
}

func (th *Theory) IsEquational() bool {
	if th == nil {
		return false
	}
	if !iterutils.All(th.clauses.Iter(), func(c *HornClause) bool { return c.IsEquational() }) {
		return false
	}
	return iterutils.All(th.ground.Iter(), func(l *Literal) bool {
		return !l.Negated() && l.IsEquality()
	})
}

func (th *Theory) IsQuasiEquational() bool {
	if th == nil {
		return false
	}
	if !iterutils.All(th.clauses.Iter(), func(c *HornClause) bool {
		return c.conclusion.IsEquality() && !c.conclusion.negated &&
			iterutils.All(c.Premise().Iter(), func(l *Literal) bool { return l.IsEquality() })
	}) {
		return false
	}
	return iterutils.All(th.ground.Iter(), func(l *Literal) bool {
		return !l.Negated() && l.IsEquality()
	})
}

func (th *Theory) ReSorted(old, new Sort) (*Theory, error) {
	if old == EmptySymbol || new == EmptySymbol {
		return nil, errs.NewFailed("cannot rename to or from empty symbol")
	}
	resortedSignature, err := th.signature.ReSorted(old, new)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to rename sort %s to %s", old, new)
	}
	resortedClauseItems, err := sliceutils.MapErrFunc(th.clauses.List(), func(c *HornClause) (*HornClause, error) {
		return c.ReSorted(new)
	})
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to rename clauses")
	}
	resortedGroundItems, err := sliceutils.MapErrFunc(th.ground.List(), func(l *Literal) (*Literal, error) {
		return l.ReSorted(new)
	})
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to rename ground literals")
	}
	return &Theory{
		signature: resortedSignature,
		clauses:   hashset.NewHashable(resortedClauseItems...),
		ground:    hashset.NewHashable(resortedGroundItems...),
	}, nil
}

func (th *Theory) IsSubTheory(of *Theory) bool {
	return of != nil &&
		th.signature.IsSubSignature(of.signature) &&
		th.clauses.IsSubSet(of.clauses) &&
		th.ground.IsSubSet(of.ground)
}

func SetTheory(sort Sort) *Theory {
	if sort == "" {
		sort = EmptySymbol
	}
	sig, err := NewSignature(sort, nil, nil, nil)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create signature for set theory"))
	}
	set, err := NewSingleSortedTheory(sig)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create set theory"))
	}
	return set
}

func MagmaTheory(sort Sort, op Operation[BinaryFunctionSymbol]) *Theory {
	Set := SetTheory(sort)
	return Extend(Set).
		EnrichWithBinaryOperation(op).
		Finalize()
}

func SemiGroupTheory(sort Sort, op Operation[BinaryFunctionSymbol]) *Theory {
	return Extend(MagmaTheory(sort, op)).
		IsAssociative(op).
		Finalize()
}

func MonoidTheory(sort Sort, op Operation[BinaryFunctionSymbol], id Operation[NullaryFunctionSymbol]) *Theory {
	return Extend(SemiGroupTheory(sort, op)).
		WithIdentityElement(id, op).
		Finalize()
}

func GroupTheory(sort Sort, op Operation[BinaryFunctionSymbol], id Operation[NullaryFunctionSymbol], inv Operation[UnaryFunctionSymbol]) *Theory {
	return Extend(MonoidTheory(sort, op, id)).
		WithInverseOperator(inv, id, op).
		Finalize()
}

func DlogHardGroupTheory(sort Sort, op Operation[BinaryFunctionSymbol], id Operation[NullaryFunctionSymbol], inv Operation[UnaryFunctionSymbol], generator Operation[NullaryFunctionSymbol]) *Theory {
	return Extend(GroupTheory(sort, op, id, inv)).
		AdjoinNonIdentityConstant(generator, id).
		Finalize()
}

func DoubleMagmaTheory(sort Sort, add, mul Operation[BinaryFunctionSymbol]) *Theory {
	out, err := CoProduct(
		MagmaTheory(sort, add),
		MagmaTheory(sort, mul),
	)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create double magma"))
	}
	return out
}

func HemiRingTheory(sort Sort, add, mul Operation[BinaryFunctionSymbol]) *Theory {
	out, err := DistributiveFuse(
		SemiGroupTheory(sort, add),
		SemiGroupTheory(sort, mul),
		sort, add, mul,
	)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create hemi-ring"))
	}
	return out
}

func SemiRingTheory(sort Sort, add, mul Operation[BinaryFunctionSymbol], one Operation[NullaryFunctionSymbol]) *Theory {
	out, err := DistributiveFuse(
		SemiGroupTheory(sort, add),
		MonoidTheory(sort, mul, one),
		sort, add, mul,
	)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create semi-ring"))
	}
	return out
}

func RigTheory(sort Sort, add, mul Operation[BinaryFunctionSymbol], zero, one Operation[NullaryFunctionSymbol]) *Theory {
	out, err := DistributiveFuse(
		MonoidTheory(sort, add, zero),
		MonoidTheory(sort, mul, one),
		sort, add, mul,
	)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create rig"))
	}
	return out
}

func EuclideanSemiDomainTheory(sort Sort, add, mul Operation[BinaryFunctionSymbol], zero, one Operation[NullaryFunctionSymbol], quo, rem Operation[BinaryFunctionSymbol], euclideanNorm Operation[UnaryFunctionSymbol]) *Theory {
	return Extend(
		RigTheory(sort, add, mul, zero, one)).
		IsCommutative(add, mul).
		EnrichWithBinaryOperation(quo, rem).
		EnrichWithUnaryOperation(euclideanNorm).
		WithEuclideanDivision(add, mul, quo, rem, zero, euclideanNorm).
		Finalize()
}

func RngTheory(sort Sort, add, mul Operation[BinaryFunctionSymbol], zero Operation[NullaryFunctionSymbol], neg Operation[UnaryFunctionSymbol]) *Theory {
	out, err := DistributiveFuse(
		GroupTheory(sort, add, zero, neg),
		SemiGroupTheory(sort, mul),
		sort, add, mul,
	)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create ring"))
	}
	return out
}

func RingTheory(sort Sort, add, mul Operation[BinaryFunctionSymbol], zero, one Operation[NullaryFunctionSymbol], neg Operation[UnaryFunctionSymbol]) *Theory {
	out, err := DistributiveFuse(
		GroupTheory(sort, add, zero, neg),
		MonoidTheory(sort, mul, one),
		sort, add, mul,
	)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create ring"))
	}
	return out
}

func EuclideanDomainTheory(sort Sort, add, mul Operation[BinaryFunctionSymbol], zero, one Operation[NullaryFunctionSymbol], neg Operation[UnaryFunctionSymbol], quo, rem Operation[BinaryFunctionSymbol], euclideanNorm Operation[UnaryFunctionSymbol]) *Theory {
	out, err := CoProduct(
		RingTheory(sort, add, mul, zero, one, neg),
		EuclideanSemiDomainTheory(sort, add, mul, zero, one, quo, rem, euclideanNorm),
	)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create euclidean domain"))
	}
	return out
}

func FieldTheory(sort Sort, add, mul Operation[BinaryFunctionSymbol], zero, one Operation[NullaryFunctionSymbol], neg, inv Operation[UnaryFunctionSymbol], quo, rem Operation[BinaryFunctionSymbol], euclideanNorm Operation[UnaryFunctionSymbol]) *Theory {
	base := EuclideanDomainTheory(sort, add, mul, zero, one, neg, quo, rem, euclideanNorm)

	x := &Variable{ID: 0, Sort: sort}
	nonZero := &Literal{
		atom:    &Equation{left: VariableTerm(x), right: ConstantTerm(zero)},
		negated: true,
	}

	ext := Extend(base).
		EnrichWithUnaryOperation(inv).
		WithInverseOperator(inv, one, mul, nonZero)

	// To ensure ring has at least two elements
	zeroNeOne := &HornClause{
		premise: nil,
		conclusion: &Literal{
			atom:    &Equation{left: ConstantTerm(zero), right: ConstantTerm(one)},
			negated: true,
		},
	}
	ext.th.clauses.Add(zeroNeOne)

	return ext.Finalize()
}

func SemiModuleTheory(
	// elements (abelian monoid)
	m Sort,
	opM Operation[BinaryFunctionSymbol],
	idM Operation[NullaryFunctionSymbol],

	// scalars
	r Sort,
	addR, mulR Operation[BinaryFunctionSymbol],
	oneR Operation[NullaryFunctionSymbol],
	// action
	scmul Operation[BinaryFunctionSymbol],
) *Theory {
	main := Extend(MonoidTheory(m, opM, idM)).IsCommutative(opM).Finalize()
	scalars := SemiRingTheory(r, addR, mulR, oneR)

	prod, err := CoProduct(main, scalars)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create semi-module theory"))
	}
	return Extend(prod).
		EnrichWithBinaryOperation(scmul).
		WithLeftIdentityElement(oneR, scmul).
		WithActionAssociativity(scmul, mulR).
		IsLeftDistributive(scmul, opM).
		IsRightDistributive(scmul, addR).
		Finalize()
}

func ModuleTheory(
	// elements (abelian group)
	sortM Sort,
	opM Operation[BinaryFunctionSymbol],
	idM Operation[NullaryFunctionSymbol],
	invM Operation[UnaryFunctionSymbol],

	// scalars (ring)
	sortR Sort,
	addR, mulR Operation[BinaryFunctionSymbol],
	zeroR, oneR Operation[NullaryFunctionSymbol],
	negR Operation[UnaryFunctionSymbol],

	// action
	scMul Operation[BinaryFunctionSymbol],
) *Theory {

	groupM := Extend(GroupTheory(sortM, opM, idM, invM)).IsCommutative(opM).Finalize()
	ringR := RingTheory(sortR, addR, mulR, zeroR, oneR, negR)

	base, err := CoProduct(groupM, ringR)
	if err != nil {
		panic(err)
	}

	return Extend(base).
		EnrichWithBinaryOperation(scMul).
		WithLeftIdentityElement(oneR, scMul).
		WithZeroAction(scMul, zeroR, idM).
		WithActionAssociativity(scMul, mulR).
		IsLeftDistributive(scMul, opM).
		IsRightDistributive(scMul, addR).
		Finalize()
}

func VectorSpaceTheory(
	// elements (abelian group)
	sortM Sort,
	opM Operation[BinaryFunctionSymbol],
	idM Operation[NullaryFunctionSymbol],
	invM Operation[UnaryFunctionSymbol],

	// scalars (field)
	sortF Sort,
	addF, mulF Operation[BinaryFunctionSymbol],
	zeroF, oneF Operation[NullaryFunctionSymbol],
	negF, invF Operation[UnaryFunctionSymbol],
	quoF, remF Operation[BinaryFunctionSymbol], euclideanNormF Operation[UnaryFunctionSymbol],

	// action
	scMul Operation[BinaryFunctionSymbol],
) *Theory {
	module := ModuleTheory(
		sortM, opM, idM, invM,
		sortF, addF, mulF, zeroF, oneF, negF,
		scMul,
	)
	scalarField := FieldTheory(
		sortF, addF, mulF, zeroF, oneF, negF,
		invF, quoF, remF, euclideanNormF,
	)
	out, err := CoProduct(module, scalarField)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create vector space theory"))
	}
	return out
}

func RAlgebraTheory(
	// elements (abelian ring)
	sortA Sort,
	addA, mulA Operation[BinaryFunctionSymbol],
	zeroA, oneA Operation[NullaryFunctionSymbol],
	negA Operation[UnaryFunctionSymbol],

	// scalars (ring)
	sortR Sort,
	addR, mulR Operation[BinaryFunctionSymbol],
	zeroR, oneR Operation[NullaryFunctionSymbol], negR Operation[UnaryFunctionSymbol],

	// action
	scMul Operation[BinaryFunctionSymbol],
) *Theory {
	moduleWithProd, err := CoProduct(
		ModuleTheory(
			sortA, addA, zeroA, negA,
			sortR, addR, mulR, zeroR, oneR, negR,
			scMul,
		),
		RingTheory(sortR, addR, mulR, zeroR, oneR, negR),
	)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create R-algebra theory"))
	}
	return Extend(moduleWithProd).
		IsCommutative(addR, mulR).
		Finalize()
}
