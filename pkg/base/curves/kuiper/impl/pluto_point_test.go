package impl_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl"
)

func Test_PlutoPointSmokeTest(t *testing.T) {
	t.Parallel()

	// SAGE:
	//   p = 0x24000000000024000130e0000d7f70e4a803ca76f439266f443f9a5cda8a6c7be4a7a5fe8fadffd6a2a7e8c30006b9459ffffcd300000001
	//   fp = GF(p)
	//   pluto = EllipticCurve(fp, [0, 57])
	//   pluto_generator = pluto(-2, 7)
	//   pluto_generator_x = pluto_generator[0]
	//   pluto_generator_y = pluto_generator[1]
	generator := new(impl.PlutoPoint).Generator()
	generatorX := generator.GetX()
	generatorY := generator.GetY()
	require.Equal(t, uint64(1), generator.IsOnCurve())
	require.Equal(t,
		dehex(t, "24000000000024000130e0000d7f70e4a803ca76f439266f443f9a5cda8a6c7be4a7a5fe8fadffd6a2a7e8c30006b9459ffffcd2ffffffff"),
		generatorX.Bytes(),
	)
	require.Equal(t,
		dehex(t, "07"),
		generatorY.Bytes(),
	)

	t.Run("double", func(t *testing.T) {
		t.Parallel()

		// SAGE:
		//   d = pluto_generator + pluto_generator
		//   dx = d[0]
		//   dy = d[1]
		d := new(impl.PlutoPoint).Double(generator)
		dx := d.GetX()
		dy := d.GetY()
		require.Equal(t,
			dehex(t, "21cbc14e5e0a94bc160416344b5d841a93477a26873ae029c2aea5cf54ff562b2a3f57e9c05a3417dc9da10aa735551cca72ed585e0a72f6"),
			dx.Bytes(),
		)
		require.Equal(t,
			dehex(t, "01e3a373af64c3f112b8acf7caf881d1c8a1696981fe856025e9f6302952a569c459677f8d2340eca9bfab304c2131479278e8b241ade693"),
			dy.Bytes(),
		)
	})

	t.Run("add", func(t *testing.T) {
		t.Parallel()

		// SAGE:
		//   e = pluto_generator + pluto_generator + pluto_generator
		//   ex = e[0]
		//   ey = e[1]
		ePrime := new(impl.PlutoPoint).Add(generator, generator)
		e := new(impl.PlutoPoint).Add(ePrime, generator)
		ex := e.GetX()
		ey := e.GetY()
		require.Equal(t,
			dehex(t, "14503a3960baf02d5d00518f7970eabe7637cb12fc8ae1053072f33af29a1a672381c6461b44a5541bea12164cbe8a3943f30445e645e725"),
			ex.Bytes(),
		)
		require.Equal(t,
			dehex(t, "1ce7fef20b25d3650a7cc7d62b5c6535756dcfeec960bebfc3b093e81aff5c67823fe64af4a725962667e8bf219211243642f3c5c152a90e"),
			ey.Bytes(),
		)
	})

	t.Run("mul", func(t *testing.T) {
		t.Parallel()

		// SAGE:
		//   r = pluto.random_element()
		//   hex(r[0])
		//   '0xcee7474dc5f5fef50c50901bea4053581c5614e841ec8bd54f0d30b36a540a6c1fa312ae4171d3be42178eda9008b74fd8ad19fd8771a24'
		//   hex(r[1])
		//	'0x735710aceebc088aff62afa7b1c35ec2f31123d2e6ab90f3891923ec95f56ad8fb584e6e738d89a7822590809a0a85de36a34f601f8d639'
		//
		//   q = 0x24000000000024000130e0000d7f70e4a803ca76f439266f443f9a5c7a8a6c7be4a775fe8e177fd69ca7e85d60050af41ffffcd300000001
		//   fq = GF(q)
		//   s = fq.random_element()
		//   hex(s)
		//   '0xdb5b883a0dfc5ec7db0959dd4128585d0402f9e807a0b69706f7d1ee3b8bca1858339b3c518614fc5cb6a672db99c73d1f659289b7e2ba6'
		//
		//   rs = r * s
		//   hex(rs[0])
		//   '0x1cfa1c6dbd0ba205394fe9af597a12283a88998b57b8ed20f1cd40f1796ec9d12e3265ca9b7aa7e572d1bcbe245bb34d9e4b973b4c93f939'
		//   hex(rs[1])
		//   '0x21f69a891686f86c232bfc195d050efbd8d820ebef05034b5ddbe6066d8fd77a261d22ed5e049595f3d6dacd09ae39710565ced53544acda'

		rxBytes := dehex(t, "0cee7474dc5f5fef50c50901bea4053581c5614e841ec8bd54f0d30b36a540a6c1fa312ae4171d3be42178eda9008b74fd8ad19fd8771a24")
		ryBytes := dehex(t, "0735710aceebc088aff62afa7b1c35ec2f31123d2e6ab90f3891923ec95f56ad8fb584e6e738d89a7822590809a0a85de36a34f601f8d639")
		r := new(impl.PlutoPoint)
		r.X.SetBytes(&rxBytes)
		r.Y.SetBytes(&ryBytes)
		r.Z.SetOne()

		sBytes := dehex(t, "0db5b883a0dfc5ec7db0959dd4128585d0402f9e807a0b69706f7d1ee3b8bca1858339b3c518614fc5cb6a672db99c73d1f659289b7e2ba6")
		s := new(impl.Fq)
		s.SetBytes(&sBytes)

		rs := new(impl.PlutoPoint).Mul(r, s)
		rsX := rs.GetX()
		rsY := rs.GetY()
		require.Equal(t,
			dehex(t, "1cfa1c6dbd0ba205394fe9af597a12283a88998b57b8ed20f1cd40f1796ec9d12e3265ca9b7aa7e572d1bcbe245bb34d9e4b973b4c93f939"),
			rsX.Bytes(),
		)
		require.Equal(t,
			dehex(t, "21f69a891686f86c232bfc195d050efbd8d820ebef05034b5ddbe6066d8fd77a261d22ed5e049595f3d6dacd09ae39710565ced53544acda"),
			rsY.Bytes(),
		)
	})
}
