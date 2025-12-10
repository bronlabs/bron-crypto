package znstar_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"pgregory.net/rapid"
)

func RSAUnitGenerator(t *testing.T) (*rapid.Generator[*znstar.RSAGroupElementUnknownOrder], *znstar.RSAGroupUnknownOrder) {
	t.Helper()
	group := errs2.Must1(znstar.SampleRSAGroup(1024, pcg.NewRandomised()))
	return UnitGenerator(t, group.ForgetOrder()), group.ForgetOrder()
}

func TestMultiplicativeGroupProperties_RSA(t *testing.T) {
	g, group := RSAUnitGenerator(t)
	suite := properties.MultiplicativeGroup(t, group, g)
	suite.Theory = append(
		suite.Theory,
		properties.CommutativityProperty(
			t,
			&properties.Carrier[*znstar.RSAGroupUnknownOrder, *znstar.RSAGroupElementUnknownOrder]{
				Value: group,
				Dist:  g,
			},
			properties.Multiplication[*znstar.RSAGroupElementUnknownOrder](),
		),
	)
	suite.Check(t)
}
