package bigint

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	bg "github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/bigint"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/multiplicative"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/multiplicative/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/uints"
	"github.com/cronokirby/saferith"
)

var _ multiplicative.ZnX[*ZnX, *IntX] = (*ZnX)(nil)
var _ impl.HolesZnX[*ZnX, *IntX] = (*ZnX)(nil)

type ZnX struct {
	impl.ZnX_[*ZnX, *IntX]
}

func (z *ZnX) Cardinality() *saferith.Modulus {
	// TODO: represent inf
	return nil
}

func (z *ZnX) Modulus() uints.Uint {
	// TODO: represent inf
	return nil
}

func (z *ZnX) Arithmetic() integer.Arithmetic[*IntX] {
	return bg.NewModularArithmetic[*IntX](-1, true)
}

func (*ZnX) Name() string {
	return Name
}

func (z *ZnX) Element() *IntX {
	return z.One()
}

func (z *ZnX) New(v uint64) *IntX {
	return nil
}

func (z *ZnX) Unwrap() *ZnX {
	return z
}
