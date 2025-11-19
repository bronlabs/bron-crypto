package proptest

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
)

type Property[V any] interface {
	Check() bool
}

func Associativeness[V base.Equatable[V]](dist Distribution[V], op func(V, V) V) Property[V] {
	return &associativeness[V]{
		dist,
		op,
	}
}

type associativeness[V base.Equatable[V]] struct {
	dist Distribution[V]
	op   func(V, V) V
}

func (p *associativeness[V]) Check() bool {
	a := p.dist.Draw()
	b := p.dist.Draw()
	c := p.dist.Draw()
	return p.op(p.op(a, b), c).Equal(p.op(a, p.op(b, c)))
}

func Commutativeness[V base.Equatable[V]](dist Distribution[V], op func(V, V) V) Property[V] {
	return &isCommutative[V]{
		dist,
		op,
	}
}

type isCommutative[V base.Equatable[V]] struct {
	dist Distribution[V]
	op   func(V, V) V
}

func (p *isCommutative[V]) Check() bool {
	a := p.dist.Draw()
	b := p.dist.Draw()
	return p.op(a, b).Equal(p.op(b, a))
}

func Idempotence[V base.Equatable[V]](dist Distribution[V], op func(V) V) Property[V] {
	return &isIdempotent[V]{
		dist,
		op,
	}
}

type isIdempotent[V base.Equatable[V]] struct {
	dist Distribution[V]
	op   func(V) V
}

func (p *isIdempotent[V]) Check() bool {
	a := p.dist.Draw()
	return p.op(p.op(a)).Equal(p.op(a))
}
