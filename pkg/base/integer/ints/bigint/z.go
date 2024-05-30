package bigint

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	bg "github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/bigint"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/ints/impl"
	"github.com/cronokirby/saferith"
)

var _ integer.Z[*Z, *Int] = (*Z)(nil)
var _ impl.HolesZ[*Z, *Int] = (*Z)(nil)

type Z struct {
	impl.Z_[*Z, *Int]
}

func (z *Z) Cardinality() *saferith.Modulus {
	// TODO: represent inf
	return nil
}

func (*Z) Name() string {
	return zName
}

func (n *Z) Arithmetic() integer.Arithmetic[*Int] {
	return bg.NewSignedArithmetic[*Int](-1, false)
}

func (z *Z) Element() *Int {
	return z.One()
}

func (z *Z) New(v uint64) *Int {
	return nil
}

func (z *Z) Unwrap() *Z {
	return z
}
