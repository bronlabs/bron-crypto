package proptest

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

func NewGeneratorNonZero[V algebra.FieldElement[V]](generator Generator[V]) Generator[V] {
	return &generatorNonZero[V]{
		generator,
	}
}

func NewFieldProperty[V algebra.FieldElement[V]](generator Generator[V], field algebra.Field[V]) Property[V] {
	associativityOfAddition := NewBinaryOpAssociative(generator, func(a, b V) V { return a.Add(b) })
	associativityOfMultiplication := NewBinaryOpAssociative(generator, func(a, b V) V { return a.Mul(b) })
	commutativityOfAddition := NewBinaryOpCommutativity(generator, func(a, b V) V { return a.Add(b) })
	commutativityOfMultiplication := NewBinaryOpCommutativity(generator, func(a, b V) V { return a.Mul(b) })
	additiveIdentity := NewBinaryOpIdentity(generator, field.Zero(), func(a, b V) V { return a.Add(b) })
	multiplicativeIdentity := NewBinaryOpIdentity(generator, field.One(), func(a, b V) V { return a.Mul(b) })
	additiveInverse := NewOpInverse(generator, field.Zero(), func(a V) V { return a.Neg() }, func(a, b V) V { return a.Add(b) })
	multiplicativeInverse := NewOpTryInverse(NewGeneratorNonZero(generator), field.One(), func(a V) (V, error) { return a.TryInv() }, func(a, b V) V { return a.Mul(b) })
	distributivityOfMultiplicationOverAddition := NewOpDistributivity(generator, func(a, b V) V { return a.Mul(b) }, func(a, b V) V { return a.Add(b) })

	return &fieldProperty[V]{
		generator,
		[]Property[V]{
			associativityOfAddition,
			associativityOfMultiplication,
			commutativityOfAddition,
			commutativityOfMultiplication,
			additiveIdentity,
			multiplicativeIdentity,
			additiveInverse,
			multiplicativeInverse,
			distributivityOfMultiplicationOverAddition,
		}}
}

type generatorNonZero[V algebra.FieldElement[V]] struct {
	generator Generator[V]
}

func (g *generatorNonZero[V]) Generate(prng io.Reader) V {
	v := g.generator.Generate(prng)
	for v.IsZero() {
		v = g.generator.Generate(prng)
	}
	return v
}

type fieldProperty[V algebra.FieldElement[V]] struct {
	generator       Generator[V]
	fieldProperties []Property[V]
}

func (p *fieldProperty[V]) Check(prng io.Reader) bool {
	for _, prop := range p.fieldProperties {
		if !prop.Check(prng) {
			return false
		}
	}

	return true
}
