package algebra

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/combinatorics"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
)

type MorphismComposition[X, Y, Z Object, x, y, z Element] interface {
	Compose(left Morphism[X, Y, x, y], right Morphism[Y, Z, y, z]) Morphism[X, Z, x, z]
}

type Object any
type Collection[Obj Object] ds.AbstractSet[Obj]
type Class[Obj Object] Collection[Obj]

type Morphism[Dom, CoDom Object, X, Y Element] interface {
	Map(x X) (Y, error)

	Dom() Dom
	Cod() CoDom
}

type EndoMorphism[O Object, X Element] Morphism[O, O, X, X]

type IsoMorphism[Dom, CoDom Object, X, Y Element] interface {
	Morphism[Dom, CoDom, X, Y]
	Inverse() Morphism[CoDom, Dom, Y, X]
}

type AutoMorphism[O Object, X Element] interface {
	EndoMorphism[O, X]
	IsoMorphism[O, O, X, X]
}

type MultiMorphism interface {
	Arity() uint
}

type BinaryMorphism[SourceType1, SourceType2, TargetType Object, SourceObjectType1, SourceObjectType2, TargetObjectType Element] interface {
	MultiMorphism
	Map(x SourceObjectType1, y SourceObjectType2) (TargetObjectType, error)
}

type BinaryEndoMorphism[O Object, X Element] BinaryMorphism[O, O, O, X, X, X]

type BinaryIsoMorphism[SourceType1, SourceType2, TargetType Object, SourceObjectType1, SourceObjectType2, TargetObjectType Element] interface {
	BinaryMorphism[SourceType1, SourceType2, TargetType, SourceObjectType1, SourceObjectType2, TargetObjectType]
	Inverse() Morphism[TargetType, combinatorics.CartesianProduct[SourceType1, SourceType2], TargetObjectType, combinatorics.CartesianProduct[SourceObjectType1, SourceObjectType2]]
}

type BinaryAutoMorphism[O Object, X Element] interface {
	BinaryEndoMorphism[O, X]
	BinaryIsoMorphism[O, O, O, X, X, X]
}

type MultiEndoMorphism[O Object, X Element] interface {
	MultiMorphism
	Map(xs ...X) (X, error)
}

type Action[C, D Structure, X, Y Element] interface {
	BinaryMorphism[C, D, D, X, Y, Y]
	Orbit(x X) (Class[Y], error)
}
