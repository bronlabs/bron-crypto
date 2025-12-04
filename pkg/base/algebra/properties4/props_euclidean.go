package properties4

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

// EuclideanDivisionProperty verifies that a = q*b + r with 0 <= r < |b| for semi-domains.
func EuclideanDivisionProperty[S algebra.EuclideanSemiDomain[E], E algebra.EuclideanSemiDomainElement[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "Euclidean_Division",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				b := ctx.Generator().Filter(func(x E) bool {
					return !x.IsZero()
				}).Draw(rt, "b")

				q, r, err := a.EuclideanDiv(b)
				require.NoError(t, err)

				// Verify a = q*b + r
				qb := q.Mul(b)
				reconstructed := qb.Add(r)
				require.True(t, a.Equal(reconstructed), "Euclidean division failed: a != q*b + r")
			})
		},
	}
}

// EuclideanDomainDivisionProperty verifies Euclidean division for domains (with negatives).
func EuclideanDomainDivisionProperty[S algebra.EuclideanDomain[E], E algebra.EuclideanDomainElement[E]]() Property[S, E] {
	return Property[S, E]{
		Name: "EuclideanDomain_Division",
		Check: func(t *testing.T, ctx *Context[S, E]) {
			rapid.Check(t, func(rt *rapid.T) {
				a := ctx.Draw(rt, "a")
				b := ctx.Generator().Filter(func(x E) bool {
					return !x.IsZero()
				}).Draw(rt, "b")

				q, r, err := a.EuclideanDiv(b)
				require.NoError(t, err)

				// Verify a = q*b + r
				qb := q.Mul(b)
				reconstructed := qb.Add(r)
				require.True(t, a.Equal(reconstructed), "Euclidean domain division failed: a != q*b + r")
			})
		},
	}
}

// EuclideanSemiDomainProperties returns properties for testing a Euclidean semi-domain.
func EuclideanSemiDomainProperties[S algebra.EuclideanSemiDomain[E], E algebra.EuclideanSemiDomainElement[E]]() []Property[S, E] {
	return []Property[S, E]{
		EuclideanDivisionProperty[S, E](),
	}
}

// EuclideanDomainProperties returns properties for testing a Euclidean domain.
func EuclideanDomainProperties[S algebra.EuclideanDomain[E], E algebra.EuclideanDomainElement[E]]() []Property[S, E] {
	return []Property[S, E]{
		EuclideanDomainDivisionProperty[S, E](),
	}
}
