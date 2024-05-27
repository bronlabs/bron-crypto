package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/stretchr/testify/require"
)

type VectorSpaceInvariants[
	VST algebra.VectorSpace[VST, BFT, VT, ST],
	BFT algebra.VectorSpaceBaseField[VST, BFT, VT, ST],
	VT algebra.Vector[VST, BFT, VT, ST],
	ST algebra.VectorSpaceScalar[VST, BFT, VT, ST]] struct{}

type VectorSpaceBaseFieldInvariants[
	VST algebra.VectorSpace[VST, BFT, VT, ST],
	BFT algebra.VectorSpaceBaseField[VST, BFT, VT, ST],
	VT algebra.Vector[VST, BFT, VT, ST],
	ST algebra.VectorSpaceScalar[VST, BFT, VT, ST]] struct{}

type VectorInvariants[
	VST algebra.VectorSpace[VST, BFT, VT, ST],
	BFT algebra.VectorSpaceBaseField[VST, BFT, VT, ST],
	VT algebra.Vector[VST, BFT, VT, ST],
	ST algebra.VectorSpaceScalar[VST, BFT, VT, ST]] struct{}

type VectorSpaceScalarInvariants[
	VST algebra.VectorSpace[VST, BFT, VT, ST],
	BFT algebra.VectorSpaceBaseField[VST, BFT, VT, ST],
	VT algebra.Vector[VST, BFT, VT, ST],
	ST algebra.VectorSpaceScalar[VST, BFT, VT, ST]] struct{}

type OneDimensionalVectorSpaceInvariants[ // TODO: CHECK TPYE
	VST algebra.OneDimensionalVectorSpace[VST, BFT, VT, ST],
	BFT algebra.VectorSpaceBaseField[VST, BFT, VT, ST],
	VT algebra.Vector[VST, BFT, VT, ST],
	ST algebra.VectorSpaceScalar[VST, BFT, VT, ST]] struct{}

func CheckVectorSpaceInvariantsfunc[VST algebra.VectorSpace[VST, BFT, VT, ST], BFT algebra.VectorSpaceBaseField[VST, BFT, VT, ST], VT algebra.Vector[VST, BFT, VT, ST], ST algebra.VectorSpaceScalar[VST, BFT, VT, ST]](t *testing.T, vectorSpace VST, basefielType BFT, elementGeneratorST fu.ObjectGenerator[ST], elementGeneratorVT fu.ObjectGenerator[VT]) {
	t.Helper()
	require.NotNil(t, vectorSpace)
	require.NotNil(t, elementGeneratorST)

	// CheckModulInvariants[VST, BFT, VT, ST](t, vectorSpace, basefielType, elementGeneratorVT, elementGeneratorST) // TODO: BFT Type
	CheckFieldInvariants[BFT, ST](t, basefielType, elementGeneratorST) // TODO: SHould this be Field or `finiteField` ?
}

func CheckOneDimensionalVectorSpaceInvariantsfunc[VST algebra.VectorSpace[VST, BFT, VT, ST], BFT algebra.VectorSpaceBaseField[VST, BFT, VT, ST], VT algebra.Vector[VST, BFT, VT, ST], ST algebra.VectorSpaceScalar[VST, BFT, VT, ST]](t *testing.T, vectorSpace VST, basefielType BFT, elementGeneratorST fu.ObjectGenerator[ST], elementGeneratorVT fu.ObjectGenerator[VT]) {
	t.Helper()
	require.NotNil(t, vectorSpace)
	require.NotNil(t, elementGeneratorST)

	CheckVectorSpaceInvariantsfunc[VST, BFT, VT, ST](t, vectorSpace, basefielType, elementGeneratorST, elementGeneratorVT)
	// CheckOneDimensionalModuleInvariants[VST, BFT, VT, ST](t, vectorSpace, basefielType, elementGeneratorVT, elementGeneratorST)
}
