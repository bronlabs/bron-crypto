package bigint

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
	bg "github.com/copperexchange/krypton-primitives/pkg/base/integer/impl/bigint"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer/natplus/impl"
)

var _ integer.NPlus[*NPlus, *NatPlus] = (*NPlus)(nil)
var _ impl.HolesNaturalPreSemiRing[*NPlus, *NatPlus] = (*NPlus)(nil)

var _ impl.HolesNPlus[*NPlus, *NatPlus] = (*NPlus)(nil)

type NPlus struct {
	impl.NPlus[*NPlus, *NatPlus]
}

func (np *NPlus) Arithmetic() integer.Arithmetic[*NatPlus] {
	return bg.NewUnsignedPositiveArithmetic[*NatPlus](-1, false)
}

func (np *NPlus) Name() string {
	return Name
}

func (np *NPlus) Unwrap() *NPlus {
	return np
}

func (np *NPlus) domain() algebra.Set[*NatPlus] {
	return np.Element().Structure()
}

func (np *NPlus) Successor() algebra.Successor[*NatPlus] {
	return integer.NewSuccessorOperator(np.Arithmetic(), np.domain)
}

func (np *NPlus) Element() *NatPlus {
	return np.One()
}

func (np *NPlus) New(v uint64) *NatPlus {
	return NewNatPlus(v)
}
