package proptest

import (
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

type Property[V any] interface {
	Check(t *testing.T, generator Generator[V], prng io.Reader) bool
}

func NewBinaryOpAssociative[V base.Equatable[V]](op func(V, V) V) Property[V] {
	return &binaryOpAssociativeProperty[V]{op}
}

func NewBinaryOpCommutativity[V base.Equatable[V]](op func(V, V) V) Property[V] {
	return &binaryOpCommutativeProperty[V]{op}
}

func NewBinaryOpIdentity[V base.Equatable[V]](id V, op func(V, V) V) Property[V] {
	ret
}

type binaryOpAssociativeProperty[V base.Equatable[V]] struct {
	op func(V, V) V
}

func (p *binaryOpAssociativeProperty[V]) Check(t *testing.T, generator Generator[V], prng io.Reader) bool {
	a := generator.Generate(t, prng)
	b := generator.Generate(t, prng)
	c := generator.Generate(t, prng)
	return p.op(p.op(a, b), c).Equal(p.op(a, p.op(b, c)))
}

type binaryOpCommutativeProperty[V base.Equatable[V]] struct {
	op func(V, V) V
}

func (p *binaryOpCommutativeProperty[V]) Check(t *testing.T, generator Generator[V], prng io.Reader) bool {
	a := generator.Generate(t, prng)
	b := generator.Generate(t, prng)
	return p.op(a, b).Equal(p.op(b, a))
}

type binaryOpIdentityProperty[V base.Equatable[V]] struct {
	id V
	op func(V, V) V
}

func (p *binaryOpIdentityProperty[V]) Check(t *testing.T, generator Generator[V], prng io.Reader) bool {
	a := generator.Generate(t, prng)
	return p.op(a, p.id).Equal(a)
}

type fieldProperty[V algebra.FieldElement[V]] struct {
	fieldProperties []Property[V]
}

func NewFieldProperty[V algebra.FieldElement[V]]() Property[V] {
	var props []Property[V]
	props = append(props, NewBinaryOpAssociative(func(a, b V) V { return a.Add(b) }))
	props = append(props, NewBinaryOpAssociative(func(a, b V) V { return a.Mul(b) }))
	props = append(props, NewBinaryOpCommutativity(func(a, b V) V { return a.Add(b) }))
	props = append(props, NewBinaryOpCommutativity(func(a, b V) V { return a.Mul(b) }))
	props = append(props)

	return &fieldProperty[V]{props}
}

func (p *fieldProperty[V]) Check(t *testing.T, generator Generator[V], prng io.Reader) bool {
	for _, prop := range p.fieldProperties {
		if !prop.Check(t, generator, prng) {
			return false
		}
	}

	return true
}
