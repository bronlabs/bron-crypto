package impl_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl"
)

func Test_TritonPointSmokeTest(t *testing.T) {
	t.Parallel()

	// sage: fp2.<u> = GF((p, 2), modulus=x^2+5)
	// sage: triton = EllipticCurve(fp2, [0, u + 3])
	// sage: fq = GF(q)
	// sage: a = triton.random_point()
	// sage: hex(a[0][0])
	// '0xa60f9cd12ec889dce3e693a7aae06e93f138b40d5f29bbedac528a1f4154a907afe175311127fb39c87bf4aac2a2ad2213be7d3decf05a8'
	// sage: hex(a[0][1])
	// '0x13471fa536160a0f9bf1f2dd7958e22568b34c7034bfec5e879d9f71a59148733281b840c64847fa8d0ce8017e24996f0a7eb611e9ab5774'
	// sage: hex(a[1][0])
	// '0x13b5dfa3177ba192db194f16ca71909efc507e2db4204a5096e44369b80f926124b66dac785a4bab910d33010146ba5bc9088a1946d6ecf0'
	// sage: hex(a[1][1])
	// '0xf9e229afe5e5f70f212648d49696bb4febd98dab235cfa52bd33ff61b827adb7472815db7489a7cd6a917972280b4da6913890019cb3ce2'
	a := new(impl.TritonPoint)
	x0Bytes := dehex(t, "0a60f9cd12ec889dce3e693a7aae06e93f138b40d5f29bbedac528a1f4154a907afe175311127fb39c87bf4aac2a2ad2213be7d3decf05a8")
	x1Bytes := dehex(t, "13471fa536160a0f9bf1f2dd7958e22568b34c7034bfec5e879d9f71a59148733281b840c64847fa8d0ce8017e24996f0a7eb611e9ab5774")
	y0Bytes := dehex(t, "13b5dfa3177ba192db194f16ca71909efc507e2db4204a5096e44369b80f926124b66dac785a4bab910d33010146ba5bc9088a1946d6ecf0")
	y1Bytes := dehex(t, "0f9e229afe5e5f70f212648d49696bb4febd98dab235cfa52bd33ff61b827adb7472815db7489a7cd6a917972280b4da6913890019cb3ce2")
	a.X.A.SetBytes(&x0Bytes)
	a.X.B.SetBytes(&x1Bytes)
	a.Y.A.SetBytes(&y0Bytes)
	a.Y.B.SetBytes(&y1Bytes)
	a.Z.SetOne()

	t.Run("double", func(t *testing.T) {
		t.Parallel()
		//
		// sage: aa = a + a
		// sage: hex(aa[0][0])
		// '0x8fd545a693e05aef17e731e032dd142e861f83d2e3c05d3eda7ae33ec8cab896ae9c55e005c7e47880e79674e3fa8070b344024505a7f10'
		// sage: hex(aa[0][1])
		// '0x15fa7de216a0422d6b36f14ebb8352deb62ceba51fda6923a113e52d89c77614d78374c2cf6a8a5c5346df222d0922720a2424fe3ce54776'
		// sage: hex(aa[1][0])
		// '0x1525c857a27069f0678382492ae694a52637bf99bc6db51da0ef6cb63ab3ac28c6a9993a0023e2fbf9ddacf35047eaf2d76309b79f86d464'
		// sage: hex(aa[1][1])
		// '0x132944c6794aa4bd82027f5e0c40b92e688bd75a0af73c00eea0b98ce58284a0417dfea003c2c5555ba2553dd55f7c1ab46286d27843b507'
		//

		aa := new(impl.TritonPoint).Add(a, a)
		require.Equal(t,
			dehex(t, "08fd545a693e05aef17e731e032dd142e861f83d2e3c05d3eda7ae33ec8cab896ae9c55e005c7e47880e79674e3fa8070b344024505a7f10"),
			aa.GetX().A.Bytes(),
		)
		require.Equal(t,
			dehex(t, "15fa7de216a0422d6b36f14ebb8352deb62ceba51fda6923a113e52d89c77614d78374c2cf6a8a5c5346df222d0922720a2424fe3ce54776"),
			aa.GetX().B.Bytes(),
		)
		require.Equal(t,
			dehex(t, "1525c857a27069f0678382492ae694a52637bf99bc6db51da0ef6cb63ab3ac28c6a9993a0023e2fbf9ddacf35047eaf2d76309b79f86d464"),
			aa.GetY().A.Bytes(),
		)
		require.Equal(t,
			dehex(t, "132944c6794aa4bd82027f5e0c40b92e688bd75a0af73c00eea0b98ce58284a0417dfea003c2c5555ba2553dd55f7c1ab46286d27843b507"),
			aa.GetY().B.Bytes(),
		)
	})

	t.Run("add", func(t *testing.T) {
		t.Parallel()
		//
		// sage: aaa = a + a + a
		// sage: hex(aaa[0][0])
		// '0x1de79969b8995ccfe689cf63b88d582161256ebf88a9559e1b55ef6f0abd1823a088a461f60f14a79a3261fb444ca4829bff867202ecfd09'
		// sage: hex(aaa[0][1])
		// '0x14b450507eb810934a02abda1ea0e29f6b55c8b10269fc9dfb02a54f993db2176bf66bdf1e4b0dfa02e1832930341c84ddaeec25bc01a517'
		// sage: hex(aaa[1][0])
		// '0x277388924dca88649a97fe5fc8d86a2e714843f1a667bc583a1b54b08fb7c9e07271df28446d43a6da207882d2e3f6f8e51c520e0b3d18d'
		// sage: hex(aaa[1][1])
		// '0xdda4014628054dfebd195c7cb230e2651f262bc025ad0b4eb775760d0b14086eef20d01a13e46c8f465c0007971845e557f230c4999ee58'
		//

		aa := new(impl.TritonPoint).Add(a, a)
		aaa := new(impl.TritonPoint).Add(aa, a)
		require.Equal(t,
			dehex(t, "1de79969b8995ccfe689cf63b88d582161256ebf88a9559e1b55ef6f0abd1823a088a461f60f14a79a3261fb444ca4829bff867202ecfd09"),
			aaa.GetX().A.Bytes(),
		)
		require.Equal(t,
			dehex(t, "14b450507eb810934a02abda1ea0e29f6b55c8b10269fc9dfb02a54f993db2176bf66bdf1e4b0dfa02e1832930341c84ddaeec25bc01a517"),
			aaa.GetX().B.Bytes(),
		)
		require.Equal(t,
			dehex(t, "0277388924dca88649a97fe5fc8d86a2e714843f1a667bc583a1b54b08fb7c9e07271df28446d43a6da207882d2e3f6f8e51c520e0b3d18d"),
			aaa.GetY().A.Bytes(),
		)
		require.Equal(t,
			dehex(t, "0dda4014628054dfebd195c7cb230e2651f262bc025ad0b4eb775760d0b14086eef20d01a13e46c8f465c0007971845e557f230c4999ee58"),
			aaa.GetY().B.Bytes(),
		)
	})

	t.Run("mul", func(t *testing.T) {
		t.Parallel()
		//
		// sage: s = fq.random_element()
		// sage: hex(s)
		// '0x220d227f627eecb9bfa007aff486277e0bf5923a1b53a48ee5c7ac845139717ec22b8ac199d9363da998cd55f38c0b6244293096eabfb41d'
		// sage: b = a * s
		// sage: hex(b[0][0])
		// '0x16e7415ca94590c5b5f0143088fb5e181fc0b2f8f6d916ea5e341f0d2f25ea2f1a00f00f9ba2e84a82e85df1dcd3926a8930f857f52a5bf0'
		// sage: hex(b[0][1])
		// '0xbfedd3d7c6bbd6ab64989bebe7b76764821de9fcfd475cebc2da0a65fd8cecb0c75784aba40c67d437507921118f66e47f51eacaceecaaa'
		// sage: hex(b[1][0])
		// '0x179c2729fbf67f94aeb913b1b47db83c629fef5d98db02e79cb93cbbabc6062310fd95efa343baa7af87d0bace76236f2c4bca1c8c22f63f'
		// sage: hex(b[1][1])
		// '0x126c8b0f79dc6a8a34099f09ebc8155b7d5a02a2f5766f3323407d67bd145274e8b5ee39fadbe13121ef2d6091184c2acb30b8f2ca1c2c3'
		//

		sBytes := dehex(t, "220d227f627eecb9bfa007aff486277e0bf5923a1b53a48ee5c7ac845139717ec22b8ac199d9363da998cd55f38c0b6244293096eabfb41d")
		s, _ := new(impl.Fq).SetBytes(&sBytes)

		b := new(impl.TritonPoint).Mul(a, s)
		require.Equal(t,
			dehex(t, "16e7415ca94590c5b5f0143088fb5e181fc0b2f8f6d916ea5e341f0d2f25ea2f1a00f00f9ba2e84a82e85df1dcd3926a8930f857f52a5bf0"),
			b.GetX().A.Bytes(),
		)
		require.Equal(t,
			dehex(t, "0bfedd3d7c6bbd6ab64989bebe7b76764821de9fcfd475cebc2da0a65fd8cecb0c75784aba40c67d437507921118f66e47f51eacaceecaaa"),
			b.GetX().B.Bytes(),
		)
		require.Equal(t,
			dehex(t, "179c2729fbf67f94aeb913b1b47db83c629fef5d98db02e79cb93cbbabc6062310fd95efa343baa7af87d0bace76236f2c4bca1c8c22f63f"),
			b.GetY().A.Bytes(),
		)
		require.Equal(t,
			dehex(t, "0126c8b0f79dc6a8a34099f09ebc8155b7d5a02a2f5766f3323407d67bd145274e8b5ee39fadbe13121ef2d6091184c2acb30b8f2ca1c2c3"),
			b.GetY().B.Bytes(),
		)
	})
}
