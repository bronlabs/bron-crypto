package znstar_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"pgregory.net/rapid"
)

func UnitGenerator[U znstar.Unit[U]](t *testing.T, group znstar.UnitGroup[U]) *rapid.Generator[U] {
	t.Helper()
	return properties.UniformDomainGenerator(group)
}
