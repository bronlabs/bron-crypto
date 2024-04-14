package algebra

type FunctionComposition[X, Y, Z Element] MorphismComposition[Set[X], Set[Y], Set[Z], X, Y, Z]

type Function[X, Y Element] Morphism[Set[X], Set[Y], X, Y]

type IsoFunction[X, Y Element] IsoMorphism[Set[X], Set[Y], X, Y]

type EndoFunction[E Element] Function[E, E]

type AutoFunction[E Element] IsoFunction[E, E]

type BiFunction[X1, X2, Y Element] BinaryMorphism[Set[X1], Set[X2], Set[Y], X1, X2, Y]

type BiEndoFunction[E Element] BiFunction[E, E, E]

type BiIsoFunction[X1, X2, Y Element] BinaryIsoMorphism[Set[X1], Set[X2], Set[Y], X1, X2, Y]

type BiAutoFunction[E Element] interface {
	BiEndoFunction[E]
	BiIsoFunction[E, E, E]
}
