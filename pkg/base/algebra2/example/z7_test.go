package example_test

import (
	crand "crypto/rand"
	"github.com/bronlabs/krypton-primitives/pkg/base/algebra2/example"
	"github.com/bronlabs/krypton-primitives/pkg/base/algebra2/fields"
	"github.com/bronlabs/krypton-primitives/pkg/base/algebra2/groups"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
)

func Double[GE groups.GroupElement[GE]](ge GE) GE {
	return ge.Op(ge)
}

func Inc[FE fields.FieldElement[FE]](fe FE) FE {
	one := fields.GetField(fe).One()
	return fe.Add(one)
}

func Random[FE fields.FiniteFieldElement[FE]](prng io.Reader) (FE, error) {
	// TODO(aalireza): This will fail for "non-static" structures, not sure if this is OK or not thou
	var fe FE
	return fields.GetFiniteField(fe).Random(prng)
}

func Test_Double(t *testing.T) {
	fe1 := &example.Z7Element{V: 3}
	fe2 := Double(fe1)
	fe2Expected := &example.Z7Element{V: 6}
	require.True(t, fe2Expected.Equal(fe2))

	ge1, err := fields.AsMulGroupElement(fe1)
	require.NoError(t, err)
	fe3 := Double(ge1).FieldElement()
	fe3Expected := &example.Z7Element{V: 2}
	require.True(t, fe3Expected.Equal(fe3))
}

func Test_Inc(t *testing.T) {
	fe1 := &example.Z7Element{V: 5}
	fe2 := Inc(fe1)
	fe2Expected := &example.Z7Element{V: 6}
	require.True(t, fe2Expected.Equal(fe2))
}

func Test_Random(t *testing.T) {
	prng := crand.Reader
	fe, err := Random[*example.Z7Element](prng)
	require.NoError(t, err)
	require.NotNil(t, fe)
}
