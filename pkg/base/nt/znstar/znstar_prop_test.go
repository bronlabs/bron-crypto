package znstar_test

import (
	"testing"

	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
)

func UnitGenerator[U znstar.Unit[U]](t *testing.T, group znstar.UnitGroup[U]) *rapid.Generator[U] {
	t.Helper()
	return properties.UniformDomainGenerator(group)
}
