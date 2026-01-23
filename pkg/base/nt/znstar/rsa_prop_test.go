package znstar_test

import (
	"testing"

	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/errs-go/errs"
)

const rsaGroupLen = 1024

func RSAUnitGenerator(t *testing.T) (*rapid.Generator[*znstar.RSAGroupElementUnknownOrder], *znstar.RSAGroupUnknownOrder) {
	t.Helper()
	group := errs.Must1(znstar.SampleRSAGroup(rsaGroupLen, pcg.NewRandomised()))
	return UnitGenerator(t, group.ForgetOrder()), group.ForgetOrder()
}

func TestMultiplicativeGroupProperties_RSA(t *testing.T) {
	t.Parallel()
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
