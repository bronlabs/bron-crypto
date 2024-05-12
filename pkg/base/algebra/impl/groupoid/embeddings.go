package groupoid

import "github.com/copperexchange/krypton-primitives/pkg/base/algebra"

type groupoid[G algebra.Structure, E algebra.Element] struct {
	algebra.Groupoid[G, E]
}
type groupoidElement[G algebra.Structure, E algebra.Element] struct {
	algebra.GroupoidElement[G, E]
}

type additiveGroupoid[G algebra.Structure, E algebra.Element] struct {
	algebra.AdditiveGroupoid[G, E]
}
type additiveGroupoidElement[G algebra.Structure, E algebra.Element] struct {
	algebra.AdditiveGroupoidElement[G, E]
}

type multiplicativeGroupoid[G algebra.Structure, E algebra.Element] struct {
	algebra.MultiplicativeGroupoid[G, E]
}
type multiplicativeGroupoidElement[G algebra.Structure, E algebra.Element] struct {
	algebra.MultiplicativeGroupoidElement[G, E]
}

type cyclicGroupoid[G algebra.Structure, E algebra.Element] struct {
	algebra.CyclicGroupoid[G, E]
}
type cyclicGroupoidElement[G algebra.Structure, E algebra.Element] struct {
	algebra.CyclicGroupoidElement[G, E]
}
