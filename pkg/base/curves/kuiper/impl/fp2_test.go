package impl_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl"
)

func Test_Fp2SmokeTest(t *testing.T) {
	t.Parallel()
	// Check if Mul/Square/Inv works as expected as these were implemented from scratch.
	//
	// sage: a = Fp2.random_element()
	// sage: hex(a[0])
	//   '0x0ccdaacbf029ab8d9b9a9419919538acb2735369f97030c075ed370712a34edcf73d7f9d713e6cc0cc538d4c7b9f801e280b3222594169cb'
	// sage: hex(a[1])
	//   '0x08e1e95e4f915f1cae9264b92d8847b54d9ffce1ae5257733d94068526891e384c2749e307271d370cd9852189bd0d1e9b6d85e68b66cb80'
	//

	var a impl.Fp2
	a0Bytes := dehex(t, "0ccdaacbf029ab8d9b9a9419919538acb2735369f97030c075ed370712a34edcf73d7f9d713e6cc0cc538d4c7b9f801e280b3222594169cb")
	a1Bytes := dehex(t, "08e1e95e4f915f1cae9264b92d8847b54d9ffce1ae5257733d94068526891e384c2749e307271d370cd9852189bd0d1e9b6d85e68b66cb80")
	a.A.SetBytes(&a0Bytes)
	a.B.SetBytes(&a1Bytes)

	t.Run("mul", func(t *testing.T) {
		t.Parallel()
		//
		// sage: b = Fp2.random_element()
		// sage: hex(b[0])
		//   '0x140fac84670572da81ad8f82a979e71260bd489dd07b7daacdb7358bf8352ff5eb6a7ea9972e125131bbf87fe2a7883f57a8b53e9ebabb7f'
		// sage: hex(b[1])
		//   '0x0f6fc46dec387bcd5e8e1616dbafa293cfb3bda521d87f404571598aad1ad7b737d892545f9d5ac172059ce9a25608f64648587d61dd23e1'
		//
		// sage: c = a * b
		// sage: hex(c[0])
		//   '0x035a95f4b1db6357b7105bcc9edb18e42858c5e632b3ad333665c28d9206ac8838a9fb607764fd1a57a981f3030b5f3ceb1f0d36ee4c3da2'
		// sage: hex(c[1])
		//   '0x1b1aec83a25b3524fb76344b018f1bd637970dfaee1b3119242ae2c50c4c14dd8deaff323f8598a7b696561050231f95927222b70ce18ad0'
		//

		var b impl.Fp2
		b0Bytes := dehex(t, "140fac84670572da81ad8f82a979e71260bd489dd07b7daacdb7358bf8352ff5eb6a7ea9972e125131bbf87fe2a7883f57a8b53e9ebabb7f")
		b1Bytes := dehex(t, "0f6fc46dec387bcd5e8e1616dbafa293cfb3bda521d87f404571598aad1ad7b737d892545f9d5ac172059ce9a25608f64648587d61dd23e1")
		b.A.SetBytes(&b0Bytes)
		b.B.SetBytes(&b1Bytes)

		var c impl.Fp2
		c.Mul(&a, &b)
		require.Equal(t,
			dehex(t, "035a95f4b1db6357b7105bcc9edb18e42858c5e632b3ad333665c28d9206ac8838a9fb607764fd1a57a981f3030b5f3ceb1f0d36ee4c3da2"),
			c.A.Bytes(),
		)
		require.Equal(t,
			dehex(t, "1b1aec83a25b3524fb76344b018f1bd637970dfaee1b3119242ae2c50c4c14dd8deaff323f8598a7b696561050231f95927222b70ce18ad0"),
			c.B.Bytes(),
		)
	})

	t.Run("square", func(t *testing.T) {
		t.Parallel()
		//
		// sage: aa = a^2
		// sage: hex(aa[0])
		//   '0x112da44eb55a926cbddab0057ed1d3c96bb5fcd2e68b4ca4c3d1d0d9b83de479af8746c6bc516bc5d3b12d5c5c791eeacdcf3c92177c4be6'
		// sage: hex(aa[1])
		//   '0x0f290636077732d6c454aae40fc41c70e1c212c9d250c63c2e40e173ae9c04dfacbdcc7fc082b8281cde095759ba46ca3c5f143ff0d60e9a'
		//

		var aa impl.Fp2
		aa.Square(&a)
		require.Equal(t,
			dehex(t, "112da44eb55a926cbddab0057ed1d3c96bb5fcd2e68b4ca4c3d1d0d9b83de479af8746c6bc516bc5d3b12d5c5c791eeacdcf3c92177c4be6"),
			aa.A.Bytes(),
		)
		require.Equal(t,
			dehex(t, "0f290636077732d6c454aae40fc41c70e1c212c9d250c63c2e40e173ae9c04dfacbdcc7fc082b8281cde095759ba46ca3c5f143ff0d60e9a"),
			aa.B.Bytes(),
		)
	})

	t.Run("inv", func(t *testing.T) {
		t.Parallel()
		//
		// sage: d = 1/a
		// sage: hex(d[0])
		// '0x0bf419786f11a8ba4e05887d1c02e50010f6c86c52d585ec3a82a6f9b2af66f6ab1dce9176bf2c6df1d541d5af01f3ac3a0612af638b1f69'
		// sage: hex(d[1])
		// '0x1c1b983d6deae768413991fe65792c00b40731e0cfa7e68d7a153e51ff95f5ac5e08937cb93007ead3c8b4c369e760e5feb55588aa1fae07'
		//

		var d impl.Fp2
		d.Invert(&a)
		require.Equal(t,
			dehex(t, "0bf419786f11a8ba4e05887d1c02e50010f6c86c52d585ec3a82a6f9b2af66f6ab1dce9176bf2c6df1d541d5af01f3ac3a0612af638b1f69"),
			d.A.Bytes(),
		)
		require.Equal(t,
			dehex(t, "1c1b983d6deae768413991fe65792c00b40731e0cfa7e68d7a153e51ff95f5ac5e08937cb93007ead3c8b4c369e760e5feb55588aa1fae07"),
			d.B.Bytes(),
		)
	})

	t.Run("sqrt", func(t *testing.T) {
		r, c := new(impl.Fp2).Sqrt(&a)
		require.Equal(t, uint64(1), c)

		rr := new(impl.Fp2).Square(r)
		require.Equal(t, uint64(1), rr.Equal(&a))
	})
}
