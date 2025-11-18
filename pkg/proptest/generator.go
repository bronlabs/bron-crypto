package proptest

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

type Generator[V any] interface {
	Generate(rng io.Reader) V
}

type domainGenerator[V any] struct {
	domain algebra.FiniteStructure[V]
}

func NewUniformDomainGenerator[V any](domain algebra.FiniteStructure[V]) Generator[V] {
	return &domainGenerator[V]{
		domain: domain,
	}
}

func (g *domainGenerator[V]) Generate(prng io.Reader) V {
	v, err := g.domain.Random(prng)
	if err != nil {
		panic(err)
	}
	return v
}
