package universal

import (
	"encoding/binary"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

func NewVariablePool() *VariablePool {
	return &VariablePool{
		ids: make(map[Sort]int),
	}
}

type VariablePool struct {
	ids map[Sort]int
}

func (vp *VariablePool) Fresh(sort Sort) *Variable {
	if sort == EmptySymbol {
		return nil
	}
	id, exists := vp.ids[sort]
	if !exists {
		id = 0
	}
	vp.ids[sort] = id + 1
	return &Variable{
		ID:   id,
		Sort: sort,
	}
}

type Variable struct {
	ID   int
	Sort Sort
}

func (v Variable) Equal(rhs Variable) bool {
	return v.ID == rhs.ID && v.Sort == rhs.Sort
}

func (v Variable) HashCode() base.HashCode {
	return base.DeriveHashCode(binary.LittleEndian.AppendUint64(nil, uint64(v.ID)), []byte(v.Sort))
}

func (v *Variable) Clone() *Variable {
	if v == nil {
		return nil
	}
	return &Variable{
		ID:   v.ID,
		Sort: v.Sort,
	}
}

func (v *Variable) renamed(new Sort) *Variable {
	if v == nil {
		return v
	}
	return &Variable{
		ID:   v.ID,
		Sort: new,
	}
}

func VariableTerm(v *Variable) *Term { return &Term{Var: v} }

func ConstantTerm(c Operation[NullaryFunctionSymbol]) *Term { return &Term{Op: c.Profile()} }

func Apply[F FunctionSymbol](op Operation[F], args ...*Term) *Term {
	return &Term{Op: op.Profile(), Args: args}
}

type Term struct {
	Op   *OperationProfile // nil iff this node is a variable
	Args []*Term
	Var  *Variable // nil iff operation node
}

func (t *Term) ReSorted(old, new Sort) (*Term, error) {
	if new == EmptySymbol {
		return nil, errs.NewFailed("cannot rename term to empty symbol")
	}
	if old == new {
		return nil, nil
	}
	out := &Term{
		Op:   t.Op.renamed(old, new),
		Args: make([]*Term, len(t.Args)),
		Var:  t.Var.renamed(new),
	}
	var err error
	for i, arg := range t.Args {
		out.Args[i], err = arg.ReSorted(old, new)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot rename term")
		}
	}
	return out, nil
}

func (t *Term) IsVariable() bool {
	return t.Op == nil && t.Var != nil
}

func (t *Term) IsOperation() bool {
	return t.Op != nil && t.Var == nil
}

func (t *Term) Sort() Sort {
	if t.Op == nil {
		return t.Var.Sort
	}
	return t.Op.output
}

func (t *Term) Equal(rhs *Term) bool {
	if t.IsVariable() && rhs.IsVariable() {
		return t.Var.Equal(*rhs.Var)
	}
	if t.IsOperation() && rhs.IsOperation() {
		if !t.Op.Equal(rhs.Op) || len(t.Args) != len(rhs.Args) {
			return false
		}
		for i := range t.Args {
			if !t.Args[i].Equal(rhs.Args[i]) {
				return false
			}
		}
		return true
	}
	return false
}

func (t *Term) Clone() *Term {
	return &Term{
		Op:   t.Op,
		Args: slices.Clone(t.Args),
		Var:  t.Var.Clone(),
	}
}

func (t *Term) HashCode() base.HashCode {
	if t.IsVariable() {
		return t.Var.HashCode()
	}
	return t.Op.HashCode().Combine(
		sliceutils.Map[[]base.HashCode](t.Args, func(arg *Term) base.HashCode {
			return arg.HashCode()
		})...,
	)
}

type Relation interface {
	Sort() Sort
	Symbol() RelationSymbol
	Left() *Term
	Right() *Term
	ReSort(new Sort)
	clone() Relation
	base.Hashable[Relation]
}

func NewEquation(left, right *Term) (*Equation, error) {
	if left.Sort() != right.Sort() {
		return nil, errs.NewIsNil("left and right terms must have the same sort")
	}
	return &Equation{
		left:  left,
		right: right,
	}, nil
}

type Equation struct {
	left, right *Term
}

func (e *Equation) Left() *Term {
	return e.left
}

func (e *Equation) Right() *Term {
	return e.right
}

func (e *Equation) Sort() Sort {
	if e.left.Sort() != e.right.Sort() {
		return EmptySymbol
	}
	return e.left.Sort()
}

func (e *Equation) Symbol() RelationSymbol {
	return EqualitySymbol
}

func (e *Equation) Clone() *Equation {
	return &Equation{
		left:  e.left.Clone(),
		right: e.right.Clone(),
	}
}

func (e *Equation) Equal(rhs Relation) bool {
	other, ok := rhs.(*Equation)
	if !ok {
		return false
	}
	return e.left.Equal(other.left) && e.right.Equal(other.right)
}

func (e *Equation) HashCode() base.HashCode {
	return e.left.HashCode().Combine(e.right.HashCode())
}

func (e *Equation) ReSort(new Sort) {
	if e == nil {
		return
	}
	var err error
	e.left, err = e.left.ReSorted(e.left.Sort(), new)
	if err != nil {
		panic(err)
	}
	e.right, err = e.right.ReSorted(e.right.Sort(), new)
	if err != nil {
		panic(err)
	}
}

func (e *Equation) clone() Relation {
	return &Equation{
		left:  e.left.Clone(),
		right: e.right.Clone(),
	}
}

func NewLessThan(left, right *Term) (*LessThan, error) {
	if left.Sort() != right.Sort() {
		return nil, errs.NewIsNil("left and right terms must have the same sort")
	}
	return &LessThan{
		left:  left,
		right: right,
	}, nil
}

type LessThan struct {
	left, right *Term
}

func (lt *LessThan) Left() *Term {
	return lt.left
}

func (lt *LessThan) Right() *Term {
	return lt.right
}

func (lt *LessThan) Sort() Sort {
	if lt.left.Sort() != lt.right.Sort() {
		return EmptySymbol
	}
	return lt.left.Sort()
}

func (lt *LessThan) Symbol() RelationSymbol {
	return LessThanSymbol
}

func (lt *LessThan) Clone() *LessThan {
	return &LessThan{
		left:  lt.left.Clone(),
		right: lt.right.Clone(),
	}
}

func (lt *LessThan) Equal(rhs Relation) bool {
	other, ok := rhs.(*LessThan)
	if !ok {
		return false
	}
	return lt.left.Equal(other.left) && lt.right.Equal(other.right)
}

func (lt *LessThan) HashCode() base.HashCode {
	return lt.left.HashCode().Combine(lt.right.HashCode())
}

func (lt *LessThan) ReSort(new Sort) {
	if lt == nil {
		return
	}
	var err error
	lt.left, err = lt.left.ReSorted(lt.left.Sort(), new)
	if err != nil {
		panic(err)
	}
	lt.right, err = lt.right.ReSorted(lt.right.Sort(), new)
	if err != nil {
		panic(err)
	}
}

func (lt *LessThan) clone() Relation {
	return &LessThan{
		left:  lt.left.Clone(),
		right: lt.right.Clone(),
	}
}

func NewLiteral(atom Relation, negated bool) *Literal {
	return &Literal{
		atom:    atom,
		negated: negated,
	}
}

type Literal struct {
	atom    Relation
	negated bool
}

func (l *Literal) Atom() Relation {
	return l.atom
}

func (l *Literal) Negated() bool {
	return l.negated
}

func (l *Literal) IsEquality() bool {
	return l.atom.Symbol() == EqualitySymbol
}

func (l *Literal) Equal(rhs *Literal) bool {
	return l.negated == rhs.negated && l.atom.Equal(rhs.atom)
}

func (l *Literal) HashCode() base.HashCode {
	return base.DeriveHashCode(
		l.Atom().HashCode().Bytes(),
		[]byte{utils.BoolTo[byte](l.negated)},
	)
}

func (l *Literal) ReSorted(new Sort) (*Literal, error) {
	if new == EmptySymbol {
		return nil, errs.NewFailed("cannot rename literal to empty symbol")
	}
	cloned := l.atom.clone()
	cloned.ReSort(new)
	return &Literal{
		atom:    cloned,
		negated: l.negated,
	}, nil
}

func NewClause(conclusion *Equation, premises ...*Literal) *HornClause {
	return &HornClause{
		premise: hashset.NewHashable(premises...),
		conclusion: &Literal{
			atom:    conclusion,
			negated: false,
		},
	}
}

type HornClause struct {
	premise    ds.MutableSet[*Literal]
	conclusion *Literal
}

func (c *HornClause) Premise() ds.MutableSet[*Literal] {
	return c.premise
}

func (c *HornClause) Conclusion() *Literal {
	return c.conclusion
}

func (c *HornClause) IsEquational() bool {
	return c.premise.IsEmpty() && c.conclusion.IsEquality() && !c.conclusion.Negated()
}

func (c *HornClause) Equal(rhs *HornClause) bool {
	return c.premise.Equal(rhs.premise) &&
		c.conclusion.Equal(rhs.conclusion)
}

func (c HornClause) HashCode() base.HashCode {
	return c.conclusion.HashCode().Combine(
		slices.Collect(iterutils.Map(c.Premise().Iter(), func(l *Literal) base.HashCode {
			return l.HashCode()
		}))...,
	)
}

func (c *HornClause) ReSorted(new Sort) (*HornClause, error) {
	if new == EmptySymbol {
		return nil, errs.NewFailed("cannot rename clause to empty symbol")
	}
	premiseItems, err := sliceutils.MapErrFunc(c.premise.List(), func(l *Literal) (*Literal, error) { return l.ReSorted(new) })
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot rename clause")
	}
	resortedConclusion, err := c.conclusion.ReSorted(new)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot rename clause")
	}
	return &HornClause{
		premise:    hashset.NewHashable(premiseItems...),
		conclusion: resortedConclusion,
	}, nil
}
