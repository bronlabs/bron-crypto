package module

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/group"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra/impl/ring"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

type Module[M algebra.Module[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.ModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]] struct {
	group.AdditiveGroup[M, E]

	_ring func() BR

	H HolesModule[M, BR, E, S]
}

func (m Module[M, BR, E, S]) MultScalarMult(scs []S, es []E) (E, error) {
	if len(scs) != len(es) {
		return *new(E), errs.NewSize("size of scalars (%d) != size of module elements (%d)", len(scs), len(es))
	}
	var out E
	for i, e := range es {
		out = m.Add(out, e.ScalarMul(scs[i]))
	}
	return out, nil
}

func (m Module[M, BR, E, S]) ModuleScalarRing() algebra.ModuleBaseRing[M, BR, E, S] {
	return m._ring()
}

type ModuleBaseRing[M algebra.Module[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.ModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]] struct {
	ring.Ring[BR, S]

	_module func() M

	H HolesModuleBaseRing[M, BR, E, S]
}

func (r ModuleBaseRing[M, BR, E, S]) Module() algebra.Module[M, BR, E, S] {
	return r._module()
}

type OneDimensionalModule[M algebra.OneDimensionalModule[M, BR, E, S], BR algebra.ModuleBaseRing[M, BR, E, S], E algebra.OneDimensionalModuleElement[M, BR, E, S], S algebra.ModuleScalar[M, BR, E, S]] struct {
	Module[M, BR, E, S]
	group.CyclicGroup[M, E]

	H HolesOneDimensionalModule[M, BR, E, S]
}
