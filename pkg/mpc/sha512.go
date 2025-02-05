package mpc

// Sha512 simplified i.e. assume the padded message length < 1024 bits (so it fits in one block).
func Sha512(q *Gates, m []*BinaryShare) (digestShare [8]*BinaryShare) {
	h0 := q.Plain(hParams[0])
	h1 := q.Plain(hParams[1])
	h2 := q.Plain(hParams[2])
	h3 := q.Plain(hParams[3])
	h4 := q.Plain(hParams[4])
	h5 := q.Plain(hParams[5])
	h6 := q.Plain(hParams[6])
	h7 := q.Plain(hParams[7])

	w := make([]*BinaryShare, 80)
	for t := 0; t < 16; t++ {
		w[t] = m[t]
	}
	for t := 16; t < 80; t++ {
		w[t] = q.BinaryAdd(sigma1(w[t-2]), q.BinaryAdd(w[t-7], q.BinaryAdd(sigma0(w[t-15]), w[t-16])))
	}

	a := h0
	b := h1
	c := h2
	d := h3
	e := h4
	f := h5
	g := h6
	h := h7

	for t := 0; t < 80; t++ {
		t1 := q.BinaryAdd(q.BinaryAdd(q.BinaryAdd(q.BinaryAdd(h, sum1(e)), ch(q, e, f, g)), q.Plain(kParams[t])), w[t])
		t2 := q.BinaryAdd(sum0(a), maj(q, a, b, c))
		h = g
		g = f
		f = e
		e = q.BinaryAdd(d, t1)
		d = c
		c = b
		b = a
		a = q.BinaryAdd(t1, t2)
	}

	h0 = q.BinaryAdd(h0, a)
	h1 = q.BinaryAdd(h1, b)
	h2 = q.BinaryAdd(h2, c)
	h3 = q.BinaryAdd(h3, d)
	h4 = q.BinaryAdd(h4, e)
	h5 = q.BinaryAdd(h5, f)
	h6 = q.BinaryAdd(h6, g)
	h7 = q.BinaryAdd(h7, h)

	digestShare[0] = h0
	digestShare[1] = h1
	digestShare[2] = h2
	digestShare[3] = h3
	digestShare[4] = h4
	digestShare[5] = h5
	digestShare[6] = h6
	digestShare[7] = h7
	return digestShare
}

var hParams = [...]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

var kParams = [...]uint64{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
	0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
	0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
	0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
	0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
	0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
	0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
	0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
	0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
	0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
	0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
}

func sum0(a *BinaryShare) *BinaryShare {
	return a.Ror(28).Xor(a.Ror(34)).Xor(a.Ror(39))
}

func sum1(e *BinaryShare) *BinaryShare {
	return e.Ror(14).Xor(e.Ror(18)).Xor(e.Ror(41))
}

func sigma0(wi *BinaryShare) *BinaryShare {
	return wi.Ror(1).Xor(wi.Ror(8)).Xor(wi.Shr(7))
}

func sigma1(wi *BinaryShare) *BinaryShare {
	return wi.Ror(19).Xor(wi.Ror(61)).Xor(wi.Shr(6))
}

func ch(g *Gates, x, y, z *BinaryShare) *BinaryShare {
	return g.And(x, y).Xor(g.And(x.Not(), z))
}

func maj(g *Gates, x, y, z *BinaryShare) *BinaryShare {
	return g.And(x, y).Xor(g.And(x, z)).Xor(g.And(y, z))
}
