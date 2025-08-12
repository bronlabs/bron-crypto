package universal

import (
	"fmt"
)

type (
	Symbol                string
	Sort                  Symbol
	RelationSymbol        Symbol
	NullaryFunctionSymbol Symbol
	UnaryFunctionSymbol   Symbol
	BinaryFunctionSymbol  Symbol
)

type FunctionSymbol interface {
	NullaryFunctionSymbol | UnaryFunctionSymbol | BinaryFunctionSymbol
}

func Arity[F FunctionSymbol](f F) int {
	switch f := any(f).(type) {
	case NullaryFunctionSymbol:
		return 0
	case UnaryFunctionSymbol:
		return 1
	case BinaryFunctionSymbol:
		return 2
	default:
		panic(fmt.Sprintf("unknown function symbol type: %T", f))
	}
}

const (
	EmptySymbol            Sort = "∅"
	PositiveIntegersSymbol Sort = "ℕ⁺"
	NaturalNumbersSymbol   Sort = "ℕ"
	IntegersSymbol         Sort = "ℤ"

	ComplementSymbol UnaryFunctionSymbol = "¬"

	EqualitySymbol           RelationSymbol = "="
	InequalitySymbol         RelationSymbol = "≠"
	LessThanSymbol           RelationSymbol = "<"
	LessThanOrEqualSymbol    RelationSymbol = "≤"
	GreaterThanSymbol        RelationSymbol = ">"
	GreaterThanOrEqualSymbol RelationSymbol = "≥"

	PlusSymbol          BinaryFunctionSymbol = "+"
	TimesSymbol         BinaryFunctionSymbol = "×"
	MinusSymbol         BinaryFunctionSymbol = "-"
	DotSymbol           BinaryFunctionSymbol = "."
	BulletSymbol        BinaryFunctionSymbol = "•"
	CircleSymbol        BinaryFunctionSymbol = "∘"
	DirectSumSymbol     BinaryFunctionSymbol = "⊕"
	TensorProductSymbol BinaryFunctionSymbol = "⊗"
	MeetSymbol          BinaryFunctionSymbol = "∧"
	JoinSymbol          BinaryFunctionSymbol = "∨"
	UnionSymbol         BinaryFunctionSymbol = "∪"
	IntersectionSymbol  BinaryFunctionSymbol = "∩"
)

func StringifyInfixBinary[F BinaryFunctionSymbol, T ~string](op F, left, right T) string {
	return fmt.Sprintf("(%s %s %s)", left, op, right)
}

func StringifyPrefixBinary[F BinaryFunctionSymbol, T ~string](op F, left, right T) string {
	return fmt.Sprintf("%s(%s, %s)", op, left, right)
}

func StringifyPrefixUnary[F UnaryFunctionSymbol, T ~string](op F, arg T) string {
	return fmt.Sprintf("%s%s", op, arg)
}

func StringifyFunctionalUnary[F UnaryFunctionSymbol, T ~string](op F, arg T) string {
	return fmt.Sprintf("%s(%s)", op, arg)
}

func StringifyPostfixUnary[F UnaryFunctionSymbol, T ~string](op F, arg T) string {
	return fmt.Sprintf("%s%s", arg, op)
}

func Subscript[O, A, B ~string](input A, subscript B) O {
	if subscript == "" {
		return O(input)
	}
	return O(fmt.Sprintf("%s_%s", input, subscript))
}

func IdentitySymbol(f BinaryFunctionSymbol) NullaryFunctionSymbol {
	return Subscript[NullaryFunctionSymbol]("𝟙", f)
}

func InverseSymbol(f BinaryFunctionSymbol) UnaryFunctionSymbol {
	return Subscript[UnaryFunctionSymbol]("⁻¹", f)
}

func (c NullaryFunctionSymbol) Symbol() NullaryFunctionSymbol {
	return c
}

func (c NullaryFunctionSymbol) Format(state fmt.State, verb rune) {
	if verb == 's' && state.Flag('+') {
		fmt.Fprintf(state, "%s (%d)", string(c), 0)
		return
	}
	fmt.Fprintf(state, "%"+string(verb), Symbol(c))
}

func (c NullaryFunctionSymbol) Arity() int {
	return 0
}

func (u UnaryFunctionSymbol) Symbol() UnaryFunctionSymbol {
	return u
}

func (u UnaryFunctionSymbol) Format(state fmt.State, verb rune) {
	if verb == 's' && state.Flag('+') {
		fmt.Fprintf(state, "%s (%d)", string(u), 1)
		return
	}
	fmt.Fprintf(state, "%"+string(verb), Symbol(u))
}

func (u UnaryFunctionSymbol) Arity() int {
	return 1
}

func (b BinaryFunctionSymbol) Symbol() BinaryFunctionSymbol {
	return b
}

func (b BinaryFunctionSymbol) Format(state fmt.State, verb rune) {
	if verb == 's' && state.Flag('+') {
		fmt.Fprintf(state, "%s (%d)", string(b), 2)
		return
	}
	fmt.Fprintf(state, "%"+string(verb), Symbol(b))
}

func (b BinaryFunctionSymbol) Arity() int {
	return 2
}
