package universal

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
)

func Extend(th *Theory) *TheoryExtension {
	if th == nil {
		th = SetTheory(EmptySymbol)
	}
	return &TheoryExtension{
		th: th.Clone(),
	}
}

func TriviallyExtend(th *Theory, sorts ...Sort) (*Theory, error) {
	if th == nil {
		return nil, errs.NewIsNil("theory cannot be nil")
	}
	out := th.Clone()
	for _, s := range sorts {
		if s == EmptySymbol {
			return nil, errs.NewFailed("sort cannot be empty")
		}
		if th.signature.factors.ContainsKey(s) {
			return nil, errs.NewFailed("sort %s already exists in the theory", s)
		}
		out.signature.factors.Put(s, &Signature{sort: s})
	}
	return out, nil
}

func CoProduct(ths ...*Theory) (*Theory, error) {
	if len(ths) == 0 {
		return SetTheory(EmptySymbol), nil
	}
	if len(ths) == 1 {
		return ths[0].Clone(), nil
	}
	coprod, err := iterutils.ReduceOrError(
		slices.Values(ths[1:]),
		ths[0],
		func(a, b *Theory) (*Theory, error) {
			summedSig, err := a.signature.Sum(b.signature)
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to sum signatures")
			}
			return &Theory{
				signature: summedSig,
				clauses:   a.clauses.Union(b.clauses),
				ground:    a.ground.Union(b.ground),
			}, nil
		})
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to compute tensor product of theories")
	}
	return coprod, nil
}

func DistributiveFuse(first, second *Theory, sort Sort, inner, outer Operation[BinaryFunctionSymbol]) (*Theory, error) {
	if first == nil || second == nil {
		return nil, errs.NewIsNil("theories cannot be nil")
	}
	if inner == nil || outer == nil {
		return nil, errs.NewIsNil("outer and inner operations cannot be nil")
	}
	if !OperationsAreEqual(inner, outer) {
		return nil, errs.NewFailed("outer and inner operations must be equal")
	}
	firstFactor, exists := first.signature.factors.Get(sort)
	if !exists {
		return nil, errs.NewFailed("theory must have the specified sort")
	}
	secondFactor, exists := second.signature.factors.Get(sort)
	if !exists {
		return nil, errs.NewFailed("theory must have the specified sort")
	}
	if !firstFactor.HasBinary(inner.Symbol()) || !secondFactor.HasBinary(outer.Symbol()) {
		return nil, errs.NewFailed("theories must have the required binary operations")
	}
	out, err := CoProduct(first, second)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to compute distributive fuse of theories")
	}
	return Extend(out).
		IsDistributive(outer, inner).
		Finalize(), nil
}

type TheoryExtension struct {
	th *Theory
}

func (t *TheoryExtension) Finalize() *Theory {
	return t.th.Clone()
}

func (t *TheoryExtension) assertSortsPresent(sorts ...Sort) {
	for _, s := range sorts {
		if !t.th.Sorts().Contains(s) {
			panic(errs.NewFailed("sort %s not declared in theory", s))
		}
	}
}
func (t *TheoryExtension) addEq(lhs, rhs *Term) {
	t.th.clauses.Add(NewClause(&Equation{lhs, rhs}))
}

func (t *TheoryExtension) AdjoinConstant(cs ...Operation[NullaryFunctionSymbol]) *TheoryExtension {
	for _, c := range cs {
		if c.Profile().Arity() != 0 {
			panic(errs.NewFailed("constant operations must be nullary"))
		}
		sig, exists := t.th.signature.factors.Get(c.Profile().output)
		if !exists {
			panic(errs.NewFailed("theory does not have the specified sort"))
		}
		sig.nullary[c.Symbol()] = c.Profile()
	}
	return t
}

func (t *TheoryExtension) AdjoinNonIdentityConstant(
	c Operation[NullaryFunctionSymbol],
	id Operation[NullaryFunctionSymbol],
) *TheoryExtension {
	if c.Symbol() == id.Symbol() {
		panic(errs.NewFailed("constant and identity operations must be distinct"))
	}
	t.AdjoinConstant(c)
	t.th.ground.Add(&Literal{
		atom:    &Equation{left: ConstantTerm(c), right: ConstantTerm(id)},
		negated: true,
	})

	return t
}

func (t *TheoryExtension) EnrichWithUnaryOperation(uops ...Operation[UnaryFunctionSymbol]) *TheoryExtension {
	for _, uop := range uops {
		prof := uop.Profile()
		if prof.Arity() != 1 {
			panic(errs.NewFailed("unary operations must be unary"))
		}
		if prof.IsMixed() {
			t.th.signature.mixedUnary.Add(uop.Profile())
		} else {
			sig, exists := t.th.signature.factors.Get(prof.output)
			if !exists {
				panic(errs.NewFailed("theory does not have the specified sort"))
			}
			sig.unary[uop.Symbol()] = uop.Profile()
		}
	}
	return t
}

func (t *TheoryExtension) EnrichWithBinaryOperation(bops ...Operation[BinaryFunctionSymbol]) *TheoryExtension {
	for _, bop := range bops {
		prof := bop.Profile()
		if prof.Arity() != 2 {
			panic(errs.NewFailed("binary operations must be binary"))
		}
		if prof.IsMixed() {
			t.th.signature.mixedBinary.Add(bop.Profile())
		} else {
			sig, exists := t.th.signature.factors.Get(prof.output)
			if !exists {
				panic(errs.NewFailed("theory does not have the specified sort"))
			}
			sig.binary[bop.Symbol()] = bop.Profile()
		}
	}
	return t
}

func (t *TheoryExtension) IsAssociative(bop Operation[BinaryFunctionSymbol]) *TheoryExtension {
	pool := NewVariablePool()
	s := bop.Profile().output
	t.assertSortsPresent(s)

	x, y, z := pool.Fresh(s), pool.Fresh(s), pool.Fresh(s)
	xy := Apply(bop, VariableTerm(x), VariableTerm(y))
	yz := Apply(bop, VariableTerm(y), VariableTerm(z))

	lhs := Apply(bop, xy, VariableTerm(z))
	rhs := Apply(bop, VariableTerm(x), yz)

	t.addEq(lhs, rhs)
	return t
}

func (t *TheoryExtension) WithLeftIdentityElement(
	id Operation[NullaryFunctionSymbol],
	under Operation[BinaryFunctionSymbol],
) *TheoryExtension {
	sort := under.Profile().Output()
	t.assertSortsPresent(sort)

	pool := NewVariablePool()
	x := pool.Fresh(sort)

	t.addEq(
		Apply(under, ConstantTerm(id), VariableTerm(x)),
		VariableTerm(x),
	)
	return t
}

func (t *TheoryExtension) WithRightIdentityElement(
	id Operation[NullaryFunctionSymbol],
	under Operation[BinaryFunctionSymbol],
) *TheoryExtension {
	sort := under.Profile().Output()
	t.assertSortsPresent(sort)

	pool := NewVariablePool()
	x := pool.Fresh(sort)

	t.addEq(
		Apply(under, VariableTerm(x), ConstantTerm(id)),
		VariableTerm(x),
	)
	return t
}

func (t *TheoryExtension) WithIdentityElement(
	id Operation[NullaryFunctionSymbol],
	under Operation[BinaryFunctionSymbol],
) *TheoryExtension {
	return t.
		WithLeftIdentityElement(id, under).
		WithRightIdentityElement(id, under)
}

func (t *TheoryExtension) WithLeftInverseOperator(
	inv Operation[UnaryFunctionSymbol],
	id Operation[NullaryFunctionSymbol],
	under Operation[BinaryFunctionSymbol],
	conditions ...*Literal,
) *TheoryExtension {
	sort := under.Profile().Output()
	t.assertSortsPresent(sort)

	pool := NewVariablePool()
	x := pool.Fresh(sort)

	eq := &Equation{
		left:  Apply(under, Apply(inv, VariableTerm(x)), VariableTerm(x)),
		right: ConstantTerm(id),
	}
	t.th.clauses.Add(NewClause(eq, conditions...))
	return t
}

func (t *TheoryExtension) WithRightInverseOperator(
	inv Operation[UnaryFunctionSymbol],
	id Operation[NullaryFunctionSymbol],
	under Operation[BinaryFunctionSymbol],
	conditions ...*Literal,
) *TheoryExtension {
	sort := under.Profile().Output()
	t.assertSortsPresent(sort)

	pool := NewVariablePool()
	x := pool.Fresh(sort)

	eq := &Equation{
		left:  Apply(under, VariableTerm(x), Apply(inv, VariableTerm(x))),
		right: ConstantTerm(id),
	}
	t.th.clauses.Add(NewClause(eq, conditions...))
	return t
}

func (t *TheoryExtension) WithInverseOperator(
	inv Operation[UnaryFunctionSymbol],
	id Operation[NullaryFunctionSymbol],
	under Operation[BinaryFunctionSymbol],
	conditions ...*Literal,
) *TheoryExtension {
	return t.
		WithLeftInverseOperator(inv, id, under, conditions...).
		WithRightInverseOperator(inv, id, under, conditions...)
}

func (t *TheoryExtension) IsCommutative(
	ops ...Operation[BinaryFunctionSymbol],
) *TheoryExtension {

	pool := NewVariablePool()

	for _, op := range ops {
		sort := op.Profile().output
		t.assertSortsPresent(sort)

		x, y := pool.Fresh(sort), pool.Fresh(sort)

		eq := &Equation{
			left:  Apply(op, VariableTerm(x), VariableTerm(y)),
			right: Apply(op, VariableTerm(y), VariableTerm(x)),
		}
		t.th.clauses.Add(NewClause(eq))
	}
	return t
}

func (t *TheoryExtension) IsLeftDistributive(
	outer Operation[BinaryFunctionSymbol],
	inner Operation[BinaryFunctionSymbol],
) *TheoryExtension {

	po, pi := outer.Profile(), inner.Profile()
	ensureLeftDistributiveTypes(po, pi)

	pool := NewVariablePool()
	x := pool.Fresh(po.inputs[0])
	y := pool.Fresh(pi.inputs[0])
	z := pool.Fresh(pi.inputs[1])

	lhs := Apply(outer, VariableTerm(x), Apply(inner, VariableTerm(y), VariableTerm(z)))
	rhs := Apply(inner,
		Apply(outer, VariableTerm(x), VariableTerm(y)),
		Apply(outer, VariableTerm(x), VariableTerm(z)),
	)
	t.addEq(lhs, rhs)
	return t
}

func (t *TheoryExtension) IsRightDistributive(
	outer Operation[BinaryFunctionSymbol],
	inner Operation[BinaryFunctionSymbol],
) *TheoryExtension {

	po, pi := outer.Profile(), inner.Profile()
	ensureRightDistributiveTypes(po, pi)

	pool := NewVariablePool()
	x := pool.Fresh(po.inputs[1])
	y := pool.Fresh(pi.inputs[0])
	z := pool.Fresh(pi.inputs[1])

	lhs := Apply(outer, Apply(inner, VariableTerm(y), VariableTerm(z)), VariableTerm(x))
	rhs := Apply(inner,
		Apply(outer, VariableTerm(y), VariableTerm(x)),
		Apply(outer, VariableTerm(z), VariableTerm(x)),
	)
	t.addEq(lhs, rhs)
	return t
}

func (t *TheoryExtension) IsDistributive(
	outer Operation[BinaryFunctionSymbol],
	inner Operation[BinaryFunctionSymbol],
) *TheoryExtension {
	return t.
		IsLeftDistributive(outer, inner).
		IsRightDistributive(outer, inner)
}

// WithDivisionIdentity adds the equation
//
//	a = b * quo(a,b) + rem(a,b)
//
// for a,b ranging over the *output sort of add*.
func (t *TheoryExtension) WithDivisionIdentity(
	add, mul Operation[BinaryFunctionSymbol],
	quo, rem Operation[BinaryFunctionSymbol],
) *TheoryExtension {

	sort := add.Profile().Output()
	t.assertSortsPresent(sort)

	pool := NewVariablePool()
	a := pool.Fresh(sort)
	b := pool.Fresh(sort)

	t.addEq(
		VariableTerm(a),
		Apply(add,
			Apply(mul,
				VariableTerm(b),
				Apply(quo, VariableTerm(a), VariableTerm(b))),
			Apply(rem, VariableTerm(a), VariableTerm(b)),
		),
	)
	return t
}

func (t *TheoryExtension) WithEuclideanDivision(
	add, mul Operation[BinaryFunctionSymbol],
	quo, rem Operation[BinaryFunctionSymbol],
	zero Operation[NullaryFunctionSymbol],
	norm Operation[UnaryFunctionSymbol],
) *TheoryExtension {

	// (1) division identity
	t.WithDivisionIdentity(add, mul, quo, rem)

	ringSort := add.Profile().Output()
	natSort := norm.Profile().Output()

	t.assertSortsPresent(ringSort, natSort)

	if len(norm.Profile().Inputs()) != 1 || norm.Profile().Inputs()[0] != ringSort {
		panic(errs.NewFailed("norm must take one argument of the ring sort"))
	}

	pool := NewVariablePool()
	a := pool.Fresh(ringSort)
	b := pool.Fresh(ringSort)

	nonZeroB := &Literal{
		atom:    &Equation{left: VariableTerm(b), right: ConstantTerm(zero)},
		negated: true,
	}
	r := Apply(rem, VariableTerm(a), VariableTerm(b))
	nonZeroR := &Literal{atom: &Equation{left: r, right: ConstantTerm(zero)}, negated: true}

	ineqAtom := &LessThan{
		left:  Apply(norm, r),
		right: Apply(norm, VariableTerm(b)),
	}

	clause := &HornClause{
		premise:    hashset.NewHashable(nonZeroB, nonZeroR),
		conclusion: &Literal{atom: ineqAtom},
	}
	t.th.clauses.Add(clause)
	return t
}

func (t *TheoryExtension) WithActionAssociativity(
	dot Operation[BinaryFunctionSymbol], // R×M→M
	mulR Operation[BinaryFunctionSymbol], // R×R→R
) *TheoryExtension {

	sortR, sortM, _ := classifyActionProfile(dot)
	pool := NewVariablePool()
	r, s := pool.Fresh(sortR), pool.Fresh(sortR)
	m := pool.Fresh(sortM)

	lhs := Apply(dot,
		Apply(mulR, VariableTerm(r), VariableTerm(s)),
		VariableTerm(m),
	)
	rhs := Apply(dot,
		VariableTerm(r),
		Apply(dot, VariableTerm(s), VariableTerm(m)),
	)
	t.addEq(lhs, rhs)
	return t
}

// WithZeroAction adds the annihilation law  0_R • m = 0_M
// where dot : R × M → M.
func (t *TheoryExtension) WithZeroAction(
	dot Operation[BinaryFunctionSymbol], // scalar action
	zeroR Operation[NullaryFunctionSymbol], // 0_R
	zeroM Operation[NullaryFunctionSymbol], // 0_M
) *TheoryExtension {

	_, sortM, err := classifyActionProfile(dot)
	if err != nil {
		panic(err)
	}

	pool := NewVariablePool()
	m := pool.Fresh(sortM)

	t.addEq(
		Apply(dot, ConstantTerm(zeroR), VariableTerm(m)),
		ConstantTerm(zeroM),
	)
	return t
}

// ******** Helper functions ********

func ensureLeftDistributiveTypes(out, in *OperationProfile) {
	if len(out.inputs) != 2 || len(in.inputs) != 2 {
		panic(errs.NewFailed("IsLeftDistributive expects binary operations"))
	}
	// Outer(x, Inner(y,z)) – so the 2nd input sort of outer
	// must equal the output sort of inner for the term to type‑check.
	if out.inputs[1] != in.output {
		panic(errs.NewFailed("type mismatch: outer second input sort %s ≠ inner output sort %s",
			out.inputs[1], in.output))
	}
	// Result sort must equal outer.output (= inner.output) so that
	// the equality itself is well‑typed.
	if out.output != in.output {
		panic(errs.NewFailed("outer output sort %s ≠ inner output sort %s", out.output, in.output))
	}
}

func ensureRightDistributiveTypes(out, in *OperationProfile) {
	if len(out.inputs) != 2 || len(in.inputs) != 2 {
		panic(errs.NewFailed("IsRightDistributive expects binary operations"))
	}
	// Outer(Inner(y,z), x) – outer's FIRST input must match inner's output
	if out.inputs[0] != in.output {
		panic(errs.NewFailed("type mismatch: outer first input sort %s ≠ inner output sort %s",
			out.inputs[0], in.output))
	}
	if out.output != in.output {
		panic(errs.NewFailed("outer output sort %s ≠ inner output sort %s", out.output, in.output))
	}
}

func classifyActionProfile(dot Operation[BinaryFunctionSymbol]) (Sort, Sort, error) {
	p := dot.Profile()
	if len(p.inputs) != 2 {
		return "", "", errs.NewFailed("action must be binary")
	}
	R, M := p.inputs[0], p.inputs[1]
	if p.output != M {
		return "", "", errs.NewFailed("output sort must equal second input sort")
	}
	if R == M {
		return "", "", errs.NewFailed("module action needs two distinct sorts")
	}
	return R, M, nil
}
