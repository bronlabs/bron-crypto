package proptest

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
)

type Property[V any] interface {
	Check(prng io.Reader) bool
}

func NewBinaryOpAssociative[V base.Equatable[V]](generator Generator[V], op func(V, V) V) Property[V] {
	return &binaryOpAssociativeProperty[V]{
		generator,
		op,
	}
}

func NewBinaryOpCommutativity[V base.Equatable[V]](generator Generator[V], op func(V, V) V) Property[V] {
	return &binaryOpCommutativeProperty[V]{
		generator,
		op,
	}
}

func NewBinaryOpIdentity[V base.Equatable[V]](generator Generator[V], id V, op func(V, V) V) Property[V] {
	return &binaryOpIdentityProperty[V]{
		generator,
		id,
		op,
	}
}

func NewOpInverse[V base.Equatable[V]](generator Generator[V], id V, opInv func(V) V, op func(V, V) V) Property[V] {
	return &opInverseProperty[V]{
		generator,
		id,
		opInv,
		op,
	}
}

func NewOpTryInverse[V base.Equatable[V]](generator Generator[V], id V, opInv func(V) (V, error), op func(V, V) V) Property[V] {
	return &opTryInverseProperty[V]{
		generator,
		id,
		opInv,
		op,
	}
}

func NewOpDistributivity[V base.Equatable[V]](generator Generator[V], mulOp func(V, V) V, addOp func(V, V) V) Property[V] {
	return &opDistributivityProperty[V]{
		generator,
		mulOp,
		addOp,
	}
}

type binaryOpAssociativeProperty[V base.Equatable[V]] struct {
	generator Generator[V]
	op        func(V, V) V
}

func (p *binaryOpAssociativeProperty[V]) Check(prng io.Reader) bool {
	a := p.generator.Generate(prng)
	b := p.generator.Generate(prng)
	c := p.generator.Generate(prng)
	return p.op(p.op(a, b), c).Equal(p.op(a, p.op(b, c)))
}

type binaryOpCommutativeProperty[V base.Equatable[V]] struct {
	generator Generator[V]
	op        func(V, V) V
}

func (p *binaryOpCommutativeProperty[V]) Check(prng io.Reader) bool {
	a := p.generator.Generate(prng)
	b := p.generator.Generate(prng)
	return p.op(a, b).Equal(p.op(b, a))
}

type binaryOpIdentityProperty[V base.Equatable[V]] struct {
	generator Generator[V]
	id        V
	op        func(V, V) V
}

func (p *binaryOpIdentityProperty[V]) Check(prng io.Reader) bool {
	a := p.generator.Generate(prng)
	return p.op(a, p.id).Equal(a)
}

type opTryInverseProperty[V base.Equatable[V]] struct {
	generator Generator[V]
	id        V
	opInv     func(V) (V, error)
	op        func(V, V) V
}

func (p *opTryInverseProperty[V]) Check(prng io.Reader) bool {
	a := p.generator.Generate(prng)
	aInv, ok := p.opInv(a)
	if ok != nil {
		return false
	}
	return p.op(a, aInv).Equal(p.id)
}

type opInverseProperty[V base.Equatable[V]] struct {
	generator Generator[V]
	id        V
	opInv     func(V) V
	op        func(V, V) V
}

func (p *opInverseProperty[V]) Check(prng io.Reader) bool {
	a := p.generator.Generate(prng)
	aInv := p.opInv(a)
	return p.op(a, aInv).Equal(p.id)
}

type opDistributivityProperty[V base.Equatable[V]] struct {
	generator Generator[V]
	mulOp     func(V, V) V
	addOp     func(V, V) V
}

func (p *opDistributivityProperty[V]) Check(prng io.Reader) bool {
	a := p.generator.Generate(prng)
	b := p.generator.Generate(prng)
	c := p.generator.Generate(prng)
	return p.mulOp(a, p.addOp(b, c)).Equal(p.addOp(p.mulOp(a, b), p.mulOp(a, c)))
}
