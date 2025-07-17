package model

import (
	"fmt"
)

type Symbol string

const (
	PlusSymbol          Symbol = "+"
	TimesSymbol         Symbol = "∙"
	DotSymbol           Symbol = "."
	BulletSymbol        Symbol = "•"
	CircleSymbol        Symbol = "∘"
	DirectSumSymbol     Symbol = "⊕"
	TensorProductSymbol Symbol = "⊗"
	MeetSymbol          Symbol = "∧"
	JoinSymbol          Symbol = "∨"
	UnionSymbol         Symbol = "∪"
	IntersectionSymbol  Symbol = "∩"
	ComplementSymbol    Symbol = "¬"
	EmptySymbol         Symbol = "∅"
)

func IdentitySymbol[E Element[E]](op Function[E]) Symbol {
	if op == nil {
		return EmptySymbol
	}
	return Symbol(fmt.Sprintf("𝟙_%s", op.Symbol()))
}

func InverseSymbol[E Element[E]](op Function[E]) Symbol {
	if op == nil {
		return EmptySymbol
	}
	return Symbol(fmt.Sprintf("%s⁻¹", op.Symbol()))
}
