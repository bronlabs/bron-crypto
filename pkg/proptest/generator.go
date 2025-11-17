package proptest

import (
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/stretchr/testify/require"
)

type Generator[V any] interface {
	Generate(t *testing.T, prng io.Reader) V
}

type domainGenerator[V any] struct {
	domain algebra.FiniteStructure[V]
}

func NewDomainGenerator[V any](domain algebra.FiniteStructure[V]) Generator[V] {
	return &domainGenerator[V]{
		domain: domain,
	}
}

func (g *domainGenerator[V]) Generate(t *testing.T, prng io.Reader) V {
	v, err := g.domain.Random(prng)
	require.NoError(t, err)
	return v
}
