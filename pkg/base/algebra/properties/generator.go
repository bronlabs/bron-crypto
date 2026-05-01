package properties

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/errs-go/errs"
	"pgregory.net/rapid"
)

func UniformDomainGenerator[E algebra.Element[E]](tb testing.TB, domain algebra.FiniteStructure[E]) *rapid.Generator[E] {
	tb.Helper()
	return rapid.Custom(func(t *rapid.T) E {
		entropyLen := domain.ElementSize()
		entropyData := rapid.SliceOfN(rapid.Byte(), 0, entropyLen).Draw(t, "preimage")
		return errs.Must1(domain.Hash(entropyData))
	})
}

func NonOpIdentityDomainGenerator[E algebra.MonoidElement[E]](tb testing.TB, domain interface {
	algebra.Monoid[E]
	algebra.FiniteStructure[E]
}) *rapid.Generator[E] {
	tb.Helper()
	return UniformDomainGenerator(tb, domain).Filter(func(e E) bool { return !e.IsOpIdentity() })
}
