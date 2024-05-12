package monoid

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
)

type monoid[M algebra.Structure, E algebra.Element] struct {
	algebra.Monoid[M, E]
}
type monoidElement[M algebra.Structure, E algebra.Element] struct {
	algebra.MonoidElement[M, E]
}
type additiveMonoid[M algebra.Structure, E algebra.Element] struct {
	algebra.AdditiveMonoid[M, E]
}
type additiveMonoidElement[M algebra.Structure, E algebra.Element] struct {
	algebra.AdditiveMonoidElement[M, E]
}
type multiplicativeMonoid[M algebra.Structure, E algebra.Element] struct {
	algebra.MultiplicativeMonoid[M, E]
}
type multiplicativeMonoidElement[M algebra.Structure, E algebra.Element] struct {
	algebra.MultiplicativeMonoidElement[M, E]
}
type cyclicMonoid[M algebra.Structure, E algebra.Element] struct {
	algebra.CyclicMonoid[M, E]
}
type cyclicMonoidElement[M algebra.Structure, E algebra.Element] struct {
	algebra.CyclicMonoidElement[M, E]
}
