package impl_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl"
)

func Test_ErisPointSmokeTest(t *testing.T) {
	t.Parallel()

	// if mul works it means that addition & double works as well
	t.Run("mul", func(t *testing.T) {
		t.Parallel()
		//
		// sage: eris = EllipticCurve(fq, [0, 57])
		// sage: s = fp.random_element()
		// sage: r = eris.random_element()
		// sage: rs = r * s
		// sage: hex(s)
		// '0xf0ebc2eeefdfe3ded4fb53f351076f8a13480745ef7e350e70937127d20d2d4788a889cc60b1ea154edfe3c57b94fc17b7f479d0276a707'
		// sage: hex(r[0])
		// '0x3db9f7ae95b183eb01dc22ee68a6d5bfeff4336413288872cf6f5856427b1a4901a02eba03780a8301240f5911b675abc7e710cfd198d3c'
		// sage: hex(r[1])
		// '0x193d2bf99a5b4c8107ee2c70c5e6bc596f0724b0d3cd67f236808728c03acf545f4599ef59cd9a69a2fa405308befa85c95d7b1ec0ead731'
		// sage: hex(rs[0])
		// '0x22ee9b5d330788797a20dc3fd816dc126fd806d37f96c358058207b67a327691bc569ad20ca6a7fed3283ba44f5bf9d277d54f4ec2682d12'
		// sage: hex(rs[1])
		// '0x1c8e707b96a63d89eca9d012d7497ed2d549fea70e5f80f405b6cd88763331121474d8c4d38ad76383b66e15db741ad85fb45a5e368da92d'
		//

		rxBytes := dehex(t, "03db9f7ae95b183eb01dc22ee68a6d5bfeff4336413288872cf6f5856427b1a4901a02eba03780a8301240f5911b675abc7e710cfd198d3c")
		ryBytes := dehex(t, "193d2bf99a5b4c8107ee2c70c5e6bc596f0724b0d3cd67f236808728c03acf545f4599ef59cd9a69a2fa405308befa85c95d7b1ec0ead731")
		r := new(impl.ErisPoint)
		r.X.SetBytes(&rxBytes)
		r.Y.SetBytes(&ryBytes)
		r.Z.SetOne()

		sBytes := dehex(t, "0f0ebc2eeefdfe3ded4fb53f351076f8a13480745ef7e350e70937127d20d2d4788a889cc60b1ea154edfe3c57b94fc17b7f479d0276a707")
		s := new(impl.Fp)
		s.SetBytes(&sBytes)

		rs := new(impl.ErisPoint).Mul(r, s)
		rsX := rs.GetX()
		rsY := rs.GetY()
		require.Equal(t,
			dehex(t, "22ee9b5d330788797a20dc3fd816dc126fd806d37f96c358058207b67a327691bc569ad20ca6a7fed3283ba44f5bf9d277d54f4ec2682d12"),
			rsX.Bytes(),
		)
		require.Equal(t,
			dehex(t, "1c8e707b96a63d89eca9d012d7497ed2d549fea70e5f80f405b6cd88763331121474d8c4d38ad76383b66e15db741ad85fb45a5e368da92d"),
			rsY.Bytes(),
		)
	})
}
