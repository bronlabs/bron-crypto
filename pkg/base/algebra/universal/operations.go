package universal

import (
	"reflect"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

type OperationTag string

const (
	PrimaryOperation   OperationTag = "primary"
	SecondaryOperation OperationTag = "secondary"
)

func NewOperationProfile(sorts, inputs []Sort, output Sort) (*OperationProfile, error) {
	if sorts == nil {
		return nil, errs.NewIsNil("sorts cannot be nil")
	}
	if inputs == nil {
		inputs = sliceutils.Repeat[[]Sort](EmptySymbol, len(sorts))
	}
	if len(inputs) != len(sorts) {
		return nil, errs.NewFailed("inputs must have the same length as sorts")
	}
	if sliceutils.IsSubList(inputs, sorts) {
		return nil, errs.NewFailed("inputs must be a sublist of sorts")
	}
	if slices.Contains(inputs, EmptySymbol) {
		return nil, errs.NewFailed("inputs cannot contain the empty sort")
	}
	if !slices.Contains(sorts, output) {
		return nil, errs.NewFailed("output must be one of the sorts")
	}
	return &OperationProfile{
		sorts:  sorts,
		inputs: inputs,
		output: output,
	}, nil
}

type OperationProfile struct {
	sorts  []Sort
	inputs []Sort
	output Sort
}

func (o *OperationProfile) Sorts() []Sort {
	return slices.Clone(o.sorts)
}

func (o *OperationProfile) Inputs() []Sort {
	return slices.Clone(o.inputs)
}

func (o *OperationProfile) Output() Sort {
	return o.output
}

func (o *OperationProfile) Clone() *OperationProfile {
	if o == nil {
		return nil
	}
	return &OperationProfile{
		sorts:  slices.Clone(o.sorts),
		inputs: slices.Clone(o.inputs),
		output: o.output,
	}
}

func (o *OperationProfile) IsSingleSorted() bool {
	return len(o.sorts) == 1
}

func (o *OperationProfile) Arity() int {
	return len(o.inputs)
}

func (o *OperationProfile) IsMixed() bool {
	distinct := hashset.NewComparable[Sort]()
	for _, s := range o.inputs {
		if s != EmptySymbol {
			distinct.Add(s)
		}
	}
	distinct.Add(o.output)
	return distinct.Size() > 1
}

func (o *OperationProfile) IsFactorableToSingleSorted() bool {
	return len(o.sorts) <= 1 ||
		iterutils.All(slices.Values(o.inputs), func(s Sort) bool { return s == o.output })
}

func (o *OperationProfile) IsTotal() bool {
	return slices.Equal(o.sorts, o.inputs) && !slices.Contains(o.inputs, EmptySymbol)
}

func (o *OperationProfile) Equal(other *OperationProfile) bool {
	if o == nil || other == nil {
		return o == other
	}
	return slices.Equal(o.sorts, other.sorts) &&
		slices.Equal(o.inputs, other.inputs) &&
		o.output == other.output
}

func (o *OperationProfile) HashCode() base.HashCode {
	return base.DeriveHashCode(
		sliceutils.Map(
			slices.Concat(o.Sorts(), o.Inputs(), []Sort{o.Output()}),
			func(s Sort) []byte { return []byte(s) },
		)...,
	)
}

func (o *OperationProfile) renamed(old, new Sort) *OperationProfile {
	if o == nil {
		return o
	}
	return &OperationProfile{
		sorts: sliceutils.Map(o.sorts, func(s Sort) Sort {
			if s == old {
				return new
			}
			return s
		}),
		inputs: sliceutils.Map(o.inputs, func(s Sort) Sort {
			if s == old {
				return new
			}
			return s
		}),
		output: o.output,
	}
}

type Operation[F FunctionSymbol] interface {
	Symbol() F
	Profile() *OperationProfile
}

func OperationsAreEqual[O Operation[F], F FunctionSymbol](a, b O) bool {
	return !utils.IsNil(a) && !utils.IsNil(b) &&
		a.Symbol() == b.Symbol() &&
		a.Profile() != nil && b.Profile() != nil &&
		a.Profile().Equal(b.Profile())
}

func NewOperation[F FunctionSymbol](symbol F, profile *OperationProfile) (Operation[F], error) {
	if profile == nil {
		return nil, errs.NewIsNil("profile cannot be nil")
	}
	return &op[F]{symbol: symbol, profile: profile}, nil
}

type op[F FunctionSymbol] struct {
	symbol  F
	profile *OperationProfile
}

func (o *op[F]) Symbol() F {
	return o.symbol
}

func (o *op[F]) Profile() *OperationProfile {
	return o.profile
}

// *** With semantics

func NewConstant[E Element[E]](sort Sort, symbol NullaryFunctionSymbol, value E) (*Constant[E], error) {
	if sort == EmptySymbol {
		return nil, errs.NewFailed("sort cannot be empty")
	}
	profile, err := NewOperationProfile([]Sort{sort}, []Sort{}, sort)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create operation profile")
	}
	op, err := NewOperation(symbol, profile)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create operation")
	}
	return InterpretConstant(op, value)
}

func InterpretConstant[E Element[E]](op Operation[NullaryFunctionSymbol], value E) (*Constant[E], error) {
	if op == nil {
		return nil, errs.NewIsNil("operation cannot be nil")
	}
	return &Constant[E]{
		symbol:  op.Symbol(),
		profile: op.Profile(),
		value:   value,
	}, nil
}

type Constant[E Element[E]] struct {
	symbol  NullaryFunctionSymbol
	profile *OperationProfile
	value   E
}

func (c *Constant[E]) Symbol() NullaryFunctionSymbol {
	return c.symbol
}

func (c *Constant[E]) Profile() *OperationProfile {
	return c.profile
}

func (c *Constant[E]) Equal(other *Constant[E]) bool {
	if c.symbol != other.symbol || c.profile == nil || other.profile == nil {
		return false
	}
	if !c.profile.Equal(other.profile) {
		return false
	}
	v, ok := any(c.value).(base.Equatable[E])
	if ok {
		return v.Equal(other.value)
	}
	return reflect.DeepEqual(c.value, other.value)
}

func (c *Constant[E]) HashCode() base.HashCode {
	return c.profile.HashCode().Combine(base.DeriveHashCode([]byte(c.symbol)))
}

type UnaryOperationCall[E1 Element[E1], E2 Element[E2]] func(E1) (E2, error)

type TwoSortedUnaryOperator[E1 Element[E1], E2 Element[E2]] struct {
	symbol  UnaryFunctionSymbol
	profile *OperationProfile
	call    UnaryOperationCall[E1, E2]
}

func (u *TwoSortedUnaryOperator[E1, E2]) Symbol() UnaryFunctionSymbol {
	return u.symbol
}

func (u *TwoSortedUnaryOperator[E1, E2]) Profile() *OperationProfile {
	return u.profile
}

func (u *TwoSortedUnaryOperator[E1, E2]) Call(e1 E1) (E2, error) {
	return u.call(e1)
}

func (u *TwoSortedUnaryOperator[E1, E2]) Equal(other *TwoSortedUnaryOperator[E1, E2]) bool {
	return u.symbol == other.symbol && u.profile.Equal(other.profile) &&
		reflect.ValueOf(u.call).Pointer() == reflect.ValueOf(other.call).Pointer()
}

func (u *TwoSortedUnaryOperator[E1, E2]) HashCode() base.HashCode {
	return u.profile.HashCode().Combine(base.DeriveHashCode([]byte(u.symbol)))
}

type UnaryOperator[E Element[E]] = TwoSortedUnaryOperator[E, E]

func NewUnaryOperator[E Element[E]](sort Sort, opSymbol UnaryFunctionSymbol, call UnaryOperationCall[E, E]) (*UnaryOperator[E], error) {
	operationProfile, err := NewOperationProfile([]Sort{sort}, []Sort{sort}, sort)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create operation profile")
	}
	operation, err := NewOperation(opSymbol, operationProfile)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create operation")
	}
	operator, err := InterpretUnaryOperator(operation, call)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to interpret unary operator")
	}
	return operator, nil
}

func InterpretUnaryOperator[E Element[E]](
	op Operation[UnaryFunctionSymbol], call UnaryOperationCall[E, E],
) (*UnaryOperator[E], error) {
	if op == nil {
		return nil, errs.NewIsNil("operation cannot be nil")
	}
	if call == nil {
		return nil, errs.NewIsNil("call cannot be nil")
	}
	return &UnaryOperator[E]{
		symbol:  op.Symbol(),
		profile: op.Profile(),
		call:    call,
	}, nil
}

func InterpretTwoSortedUnaryOperator[E1 Element[E1], E2 Element[E2], O Element[O]](
	op Operation[UnaryFunctionSymbol], call UnaryOperationCall[E1, E2],
) (*TwoSortedUnaryOperator[E1, E2], error) {
	if op == nil {
		return nil, errs.NewIsNil("operation cannot be nil")
	}
	if call == nil {
		return nil, errs.NewIsNil("call cannot be nil")
	}
	return &TwoSortedUnaryOperator[E1, E2]{
		symbol:  op.Symbol(),
		profile: op.Profile(),
		call:    call,
	}, nil
}

type BinaryOperationCall[X1 Element[X1], X2 Element[X2], Y Element[Y]] func(X1, X2) (Y, error)

type TwoSortedBinaryOperator[X1 Element[X1], X2 Element[X2], Y Element[Y]] struct {
	symbol  BinaryFunctionSymbol
	profile *OperationProfile
	call    BinaryOperationCall[X1, X2, Y]
}

func (b *TwoSortedBinaryOperator[X1, X2, Y]) Symbol() BinaryFunctionSymbol {
	return b.symbol
}

func (b *TwoSortedBinaryOperator[X1, X2, Y]) Profile() *OperationProfile {
	return b.profile
}

func (b *TwoSortedBinaryOperator[X1, X2, Y]) Equal(other *TwoSortedBinaryOperator[X1, X2, Y]) bool {
	return b.symbol == other.symbol && b.profile.Equal(other.profile) &&
		reflect.ValueOf(b.call).Pointer() == reflect.ValueOf(other.call).Pointer()
}

func (b *TwoSortedBinaryOperator[X1, X2, Y]) HashCode() base.HashCode {
	return b.profile.HashCode().Combine(base.DeriveHashCode([]byte(b.symbol)))
}

func (b *TwoSortedBinaryOperator[X1, X2, Y]) Call(x1 X1, x2 X2) (Y, error) {
	return b.call(x1, x2)
}

type BinaryOperator[E Element[E]] = TwoSortedBinaryOperator[E, E, E]

func NewBinaryOperator[E Element[E]](sort Sort, opSymbol BinaryFunctionSymbol, call BinaryOperationCall[E, E, E]) (*BinaryOperator[E], error) {
	operationProfile, err := NewOperationProfile([]Sort{sort}, []Sort{sort, sort}, sort)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create operation profile")
	}
	operation, err := NewOperation(opSymbol, operationProfile)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create operation")
	}
	operator, err := InterpretBinaryOperator(operation, call)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to interpret binary operator")
	}
	return operator, nil
}

func InterpretBinaryOperator[E Element[E]](
	op Operation[BinaryFunctionSymbol], call BinaryOperationCall[E, E, E],
) (*BinaryOperator[E], error) {
	if op == nil {
		return nil, errs.NewIsNil("operation cannot be nil")
	}
	if call == nil {
		return nil, errs.NewIsNil("call cannot be nil")
	}
	return &BinaryOperator[E]{
		symbol:  op.Symbol(),
		profile: op.Profile(),
		call:    call,
	}, nil
}

type LeftAction[A Element[A], X Element[X]] = TwoSortedBinaryOperator[A, X, X]

func NewLeftAction[A Element[A], X Element[X]](
	actionSort, setSort Sort, opSymbol BinaryFunctionSymbol, call BinaryOperationCall[A, X, X],
) (*LeftAction[A, X], error) {
	if actionSort == EmptySymbol || setSort == EmptySymbol {
		return nil, errs.NewFailed("actionSort and setSort cannot be empty")
	}
	profile, err := NewOperationProfile([]Sort{actionSort, setSort}, []Sort{actionSort, setSort}, setSort)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create operation profile")
	}
	op, err := NewOperation(opSymbol, profile)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create operation")
	}
	return InterpretLeftAction(op, call)
}

func InterpretLeftAction[A Element[A], X Element[X]](
	op Operation[BinaryFunctionSymbol], call BinaryOperationCall[A, X, X],
) (*LeftAction[A, X], error) {
	if op == nil {
		return nil, errs.NewIsNil("operation cannot be nil")
	}
	if call == nil {
		return nil, errs.NewIsNil("call cannot be nil")
	}
	return &LeftAction[A, X]{
		symbol:  op.Symbol(),
		profile: op.Profile(),
		call:    call,
	}, nil
}

type RightAction[A Element[A], X Element[X]] = TwoSortedBinaryOperator[X, A, X]

func NewRightAction[A Element[A], X Element[X]](
	actionSort, setSort Sort, opSymbol BinaryFunctionSymbol, call BinaryOperationCall[X, A, X],
) (*RightAction[A, X], error) {
	if actionSort == EmptySymbol || setSort == EmptySymbol {
		return nil, errs.NewFailed("actionSort and setSort cannot be empty")
	}
	profile, err := NewOperationProfile([]Sort{setSort, actionSort}, []Sort{setSort, actionSort}, setSort)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create operation profile")
	}
	op, err := NewOperation(opSymbol, profile)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create operation")
	}
	return InterpretRightAction(op, call)
}

func InterpretRightAction[A Element[A], X Element[X]](
	op Operation[BinaryFunctionSymbol], call BinaryOperationCall[X, A, X],
) (*RightAction[A, X], error) {
	if op == nil {
		return nil, errs.NewIsNil("operation cannot be nil")
	}
	if call == nil {
		return nil, errs.NewIsNil("call cannot be nil")
	}
	return &RightAction[A, X]{
		symbol:  op.Symbol(),
		profile: op.Profile(),
		call:    call,
	}, nil
}
