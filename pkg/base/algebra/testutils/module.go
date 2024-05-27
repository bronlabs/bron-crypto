package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/stretchr/testify/require"
)

type ModuleInvariants[
	MT algebra.Module[MT, BRT, MET, ST],
	BRT algebra.ModuleBaseRing[MT, BRT, MET, ST],
	MET algebra.ModuleElement[MT, BRT, MET, ST],
	ST algebra.ModuleScalar[MT, BRT, MET, ST]] struct{}
type ModuleBaseRingInvariants[
	MT algebra.Module[MT, BRT, MET, ST],
	BRT algebra.ModuleBaseRing[MT, BRT, MET, ST],
	MET algebra.ModuleElement[MT, BRT, MET, ST],
	ST algebra.ModuleScalar[MT, BRT, MET, ST]] struct{}
type ModuleElementInvariants[
	MT algebra.Module[MT, BRT, MET, ST],
	BRT algebra.ModuleBaseRing[MT, BRT, MET, ST],
	MET algebra.ModuleElement[MT, BRT, MET, ST],
	ST algebra.ModuleScalar[MT, BRT, MET, ST]] struct{}
type ModuleScalarInvariants[
	MT algebra.Module[MT, BRT, MET, ST],
	BRT algebra.ModuleBaseRing[MT, BRT, MET, ST],
	MET algebra.ModuleElement[MT, BRT, MET, ST],
	ST algebra.ModuleScalar[MT, BRT, MET, ST]] struct{}

type OneDimensionalModuleInvariants[ // TODO: Check the type
	MT algebra.OneDimensionalModule[MT, BRT, MET, ST],
	BRT algebra.ModuleBaseRing[MT, BRT, MET, ST],
	MET algebra.ModuleElement[MT, BRT, MET, ST],
	ST algebra.ModuleScalar[MT, BRT, MET, ST]] struct{}

func (mi *ModuleInvariants[MT, BRT, MET, ST]) MultiScalarMult(t *testing.T, scs []ST, es []MET) {
	t.Helper()
	// TODO
}

func (mi *ModuleInvariants[MT, BRT, MET, ST]) ModuleScalarRing(t *testing.T) {
	t.Helper()
	// TODO
}

func (mbri *ModuleBaseRingInvariants[MT, BRT, MET, ST]) Module(t *testing.T) {
	t.Helper()
	// TODO
}

func (mei *ModuleElementInvariants[MT, BRT, MET, ST]) ScalarMul(t *testing.T, sc algebra.ModuleScalar[MT, BRT, MET, ST]) {
	t.Helper()
	// TODO
}

func CheckModulInvariants[MT algebra.Module[MT, BRT, MET, ST], BRT algebra.ModuleBaseRing[MT, BRT, MET, ST], MET algebra.ModuleElement[MT, BRT, MET, ST], ST algebra.ModuleScalar[MT, BRT, MET, ST]](t *testing.T, module MT, baseRingType BRT, elementGeneratorMET fu.ObjectGenerator[MET], elementGeneratorST fu.ObjectGenerator[ST]) {
	t.Helper()
	require.NotNil(t, module)
	require.NotNil(t, elementGeneratorMET)
	CheckAdditiveGroupInvariants[MT, MET](t, module, elementGeneratorMET)
	// mi := &ModuleInvariants[MT, BRT, MET, ST]{}
	// mi.MultiScalarMult(t, scalarType, moduleEl)
	// mi.ModuleScalarRing(t)
	CheckRingInvariants[BRT, ST](t, baseRingType, elementGeneratorST)
	// mbri := &ModuleBaseRingInvariants[MT, BRT, MET, ST]{}
	// mbri.Module(t)
	// mei := &ModuleElementInvariants[MT, BRT, MET, ST]{}
	// mei.ScalarMul(t, sc)
}
func CheckOneDimensionalModuleInvariants[MT algebra.OneDimensionalModule[MT, BRT, MET, ST], BRT algebra.ModuleBaseRing[MT, BRT, MET, ST], MET algebra.ModuleElement[MT, BRT, MET, ST], ST algebra.ModuleScalar[MT, BRT, MET, ST]](t *testing.T, module MT, baseRingType BRT, elementGeneratorMET fu.ObjectGenerator[MET], elementGeneratorST fu.ObjectGenerator[ST]) {
	t.Helper()

	CheckModulInvariants[MT, BRT, MET, ST](t, module, baseRingType, elementGeneratorMET, elementGeneratorST)
	// CheckCyclicGroupInvariants[MT, MET](t, module, elementGeneratorMET) //TODO: MET type
}
