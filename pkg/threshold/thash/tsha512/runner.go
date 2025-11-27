package tsha512

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/mpc"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/binrep3"
)

var _ network.Runner[*Output] = (*Runner)(nil)

type Output struct {
	PreImageShares [4]*binrep3.Share
	ImageShare     [8]*binrep3.Share
}

type Runner struct {
	participant *Participant
}

func (p *Participant) NewRunner() network.Runner[*Output] {
	return &Runner{participant: p}
}

func (r *Runner) Run(rt *network.Router) (*Output, error) {
	std, err := mpc.NewArithmetic(rt, r.participant.id, r.participant.quorum, r.participant.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create arithmetic")
	}

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
		std.RandomSecret(),
		std.RandomSecret(),
		std.RandomSecret(),
		std.RandomSecret(),
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
		sigma0 := std.Xor(std.Xor(w[i-15].Ror(1), w[i-15].Ror(8)), w[i-15].Shr(7))
		sigma1 := std.Xor(std.Xor(w[i-2].Ror(19), w[i-2].Ror(61)), w[i-2].Shr(6))
		w[i] = std.Add(w[i-16], std.Add(sigma0, std.Add(w[i-7], sigma1)))
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
		sum0 := std.Xor(std.Xor(a.Ror(28), a.Ror(34)), a.Ror(39))
		sum1 := std.Xor(std.Xor(e.Ror(14), e.Ror(18)), e.Ror(41))

		ef := std.And(e, f)
		negEg := std.And(std.Not(e), g)
		ab := std.And(a, b)
		ac := std.And(a, c)
		bc := std.And(b, c)

		ch := std.Xor(ef, negEg)
		maj := std.Xor(std.Xor(ab, ac), bc)
		temp1 := std.Add(hh, std.Add(sum1, std.Add(ch, std.Add(k[i], w[i]))))
		temp2 := std.Add(sum0, maj)

		hh = g
		g = f
		f = e
		e = std.Add(d, temp1)
		d = c
		c = b
		b = a
		a = std.Add(temp1, temp2)
	}

	h[0] = std.Add(h[0], a)
	h[1] = std.Add(h[1], b)
	h[2] = std.Add(h[2], c)
	h[3] = std.Add(h[3], d)
	h[4] = std.Add(h[4], e)
	h[5] = std.Add(h[5], f)
	h[6] = std.Add(h[6], g)
	h[7] = std.Add(h[7], hh)

	output := &Output{
		PreImageShares: [4]*binrep3.Share{
			preimage[0].Secret(), preimage[1].Secret(), preimage[2].Secret(), preimage[3].Secret(),
		},
		ImageShare: [8]*binrep3.Share{
			h[0].Secret(), h[1].Secret(), h[2].Secret(), h[3].Secret(), h[4].Secret(), h[5].Secret(), h[6].Secret(), h[7].Secret(),
		},
	}

	return output, nil
}
