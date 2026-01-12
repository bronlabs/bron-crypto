package circuits

import (
	"github.com/bronlabs/bron-crypto/pkg/threshold/mpc"
)

// Sha512 samples random 32-bytes and computes SHA-512 hash of it.
// It returns the preimage and the hash.
func Sha512(arith *mpc.Arithmetic) ([4]*mpc.Value64, [8]*mpc.Value64) {
	h := [8]*mpc.Value64{
		mpc.NewValue64Public(0x6a09e667f3bcc908),
		mpc.NewValue64Public(0xbb67ae8584caa73b),
		mpc.NewValue64Public(0x3c6ef372fe94f82b),
		mpc.NewValue64Public(0xa54ff53a5f1d36f1),
		mpc.NewValue64Public(0x510e527fade682d1),
		mpc.NewValue64Public(0x9b05688c2b3e6c1f),
		mpc.NewValue64Public(0x1f83d9abfb41bd6b),
		mpc.NewValue64Public(0x5be0cd19137e2179),
	}

	k := [80]*mpc.Value64{
		mpc.NewValue64Public(0x428a2f98d728ae22), mpc.NewValue64Public(0x7137449123ef65cd), mpc.NewValue64Public(0xb5c0fbcfec4d3b2f), mpc.NewValue64Public(0xe9b5dba58189dbbc), mpc.NewValue64Public(0x3956c25bf348b538),
		mpc.NewValue64Public(0x59f111f1b605d019), mpc.NewValue64Public(0x923f82a4af194f9b), mpc.NewValue64Public(0xab1c5ed5da6d8118), mpc.NewValue64Public(0xd807aa98a3030242), mpc.NewValue64Public(0x12835b0145706fbe),
		mpc.NewValue64Public(0x243185be4ee4b28c), mpc.NewValue64Public(0x550c7dc3d5ffb4e2), mpc.NewValue64Public(0x72be5d74f27b896f), mpc.NewValue64Public(0x80deb1fe3b1696b1), mpc.NewValue64Public(0x9bdc06a725c71235),
		mpc.NewValue64Public(0xc19bf174cf692694), mpc.NewValue64Public(0xe49b69c19ef14ad2), mpc.NewValue64Public(0xefbe4786384f25e3), mpc.NewValue64Public(0x0fc19dc68b8cd5b5), mpc.NewValue64Public(0x240ca1cc77ac9c65),
		mpc.NewValue64Public(0x2de92c6f592b0275), mpc.NewValue64Public(0x4a7484aa6ea6e483), mpc.NewValue64Public(0x5cb0a9dcbd41fbd4), mpc.NewValue64Public(0x76f988da831153b5), mpc.NewValue64Public(0x983e5152ee66dfab),
		mpc.NewValue64Public(0xa831c66d2db43210), mpc.NewValue64Public(0xb00327c898fb213f), mpc.NewValue64Public(0xbf597fc7beef0ee4), mpc.NewValue64Public(0xc6e00bf33da88fc2), mpc.NewValue64Public(0xd5a79147930aa725),
		mpc.NewValue64Public(0x06ca6351e003826f), mpc.NewValue64Public(0x142929670a0e6e70), mpc.NewValue64Public(0x27b70a8546d22ffc), mpc.NewValue64Public(0x2e1b21385c26c926), mpc.NewValue64Public(0x4d2c6dfc5ac42aed),
		mpc.NewValue64Public(0x53380d139d95b3df), mpc.NewValue64Public(0x650a73548baf63de), mpc.NewValue64Public(0x766a0abb3c77b2a8), mpc.NewValue64Public(0x81c2c92e47edaee6), mpc.NewValue64Public(0x92722c851482353b),
		mpc.NewValue64Public(0xa2bfe8a14cf10364), mpc.NewValue64Public(0xa81a664bbc423001), mpc.NewValue64Public(0xc24b8b70d0f89791), mpc.NewValue64Public(0xc76c51a30654be30), mpc.NewValue64Public(0xd192e819d6ef5218),
		mpc.NewValue64Public(0xd69906245565a910), mpc.NewValue64Public(0xf40e35855771202a), mpc.NewValue64Public(0x106aa07032bbd1b8), mpc.NewValue64Public(0x19a4c116b8d2d0c8), mpc.NewValue64Public(0x1e376c085141ab53),
		mpc.NewValue64Public(0x2748774cdf8eeb99), mpc.NewValue64Public(0x34b0bcb5e19b48a8), mpc.NewValue64Public(0x391c0cb3c5c95a63), mpc.NewValue64Public(0x4ed8aa4ae3418acb), mpc.NewValue64Public(0x5b9cca4f7763e373),
		mpc.NewValue64Public(0x682e6ff3d6b2b8a3), mpc.NewValue64Public(0x748f82ee5defb2fc), mpc.NewValue64Public(0x78a5636f43172f60), mpc.NewValue64Public(0x84c87814a1f0ab72), mpc.NewValue64Public(0x8cc702081a6439ec),
		mpc.NewValue64Public(0x90befffa23631e28), mpc.NewValue64Public(0xa4506cebde82bde9), mpc.NewValue64Public(0xbef9a3f7b2c67915), mpc.NewValue64Public(0xc67178f2e372532b), mpc.NewValue64Public(0xca273eceea26619c),
		mpc.NewValue64Public(0xd186b8c721c0c207), mpc.NewValue64Public(0xeada7dd6cde0eb1e), mpc.NewValue64Public(0xf57d4f7fee6ed178), mpc.NewValue64Public(0x06f067aa72176fba), mpc.NewValue64Public(0x0a637dc5a2c898a6),
		mpc.NewValue64Public(0x113f9804bef90dae), mpc.NewValue64Public(0x1b710b35131c471b), mpc.NewValue64Public(0x28db77f523047d84), mpc.NewValue64Public(0x32caab7b40c72493), mpc.NewValue64Public(0x3c9ebe0a15c9bebc),
		mpc.NewValue64Public(0x431d67c49c100d4c), mpc.NewValue64Public(0x4cc5d4becb3e42b6), mpc.NewValue64Public(0x597f299cfc657e2a), mpc.NewValue64Public(0x5fcb6fab3ad6faec), mpc.NewValue64Public(0x6c44198c4a475817),
	}

	preimage := [4]*mpc.Value64{
		arith.RandomSecret(),
		arith.RandomSecret(),
		arith.RandomSecret(),
		arith.RandomSecret(),
	}

	w := [80]*mpc.Value64{
		preimage[0], preimage[1], preimage[2], preimage[3], // message
		mpc.NewValue64Public(0x8000000000000000), // padding
		mpc.NewValue64Public(0x0000000000000000), // padding
		mpc.NewValue64Public(0x0000000000000000), // padding
		mpc.NewValue64Public(0x0000000000000000), // padding
		mpc.NewValue64Public(0x0000000000000000), // padding
		mpc.NewValue64Public(0x0000000000000000), // padding
		mpc.NewValue64Public(0x0000000000000000), // padding
		mpc.NewValue64Public(0x0000000000000000), // padding
		mpc.NewValue64Public(0x0000000000000000), // padding
		mpc.NewValue64Public(0x0000000000000000), // padding
		mpc.NewValue64Public(0),                  // length hi
		mpc.NewValue64Public(256),                // length lo
	}

	for i := 16; i < 80; i++ {
		sigma0 := arith.Xor(arith.Xor(w[i-15].Ror(1), w[i-15].Ror(8)), w[i-15].Shr(7))
		sigma1 := arith.Xor(arith.Xor(w[i-2].Ror(19), w[i-2].Ror(61)), w[i-2].Shr(6))
		w[i] = arith.Sum(w[i-16], sigma0, w[i-7], sigma1)
	}

	a := h[0]
	b := h[1]
	c := h[2]
	d := h[3]
	e := h[4]
	f := h[5]
	g := h[6]
	hh := h[7]

	for i := 0; i < 80; i++ {
		sum0 := arith.Xor(arith.Xor(a.Ror(28), a.Ror(34)), a.Ror(39))
		sum1 := arith.Xor(arith.Xor(e.Ror(14), e.Ror(18)), e.Ror(41))

		andResult := arith.AndBatch(
			[]*mpc.Value64{e, arith.Not(e), a, a, b},
			[]*mpc.Value64{f, g, b, c, c},
		)
		ef := andResult[0]
		notEg := andResult[1]
		ab := andResult[2]
		ac := andResult[3]
		bc := andResult[4]

		ch := arith.Xor(ef, notEg)
		maj := arith.Xor(arith.Xor(ab, ac), bc)
		temp1 := arith.Sum(hh, sum1, ch, k[i], w[i])
		temp2 := arith.Add(sum0, maj)

		ea := arith.AddBatch([]*mpc.Value64{d, temp1}, []*mpc.Value64{temp1, temp2})
		hh = g
		g = f
		f = e
		e = ea[0]
		d = c
		c = b
		b = a
		a = ea[1]
	}

	newH := arith.AddBatch(
		[]*mpc.Value64{h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]},
		[]*mpc.Value64{a, b, c, d, e, f, g, hh},
	)
	h[0] = newH[0]
	h[1] = newH[1]
	h[2] = newH[2]
	h[3] = newH[3]
	h[4] = newH[4]
	h[5] = newH[5]
	h[6] = newH[6]
	h[7] = newH[7]

	println(arith.Rounds())
	return preimage, h
}
