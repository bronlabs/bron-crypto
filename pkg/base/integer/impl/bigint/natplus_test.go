package bigint_test

// func TestBigInt(t *testing.T) {
// 	t.Parallel()

// 	two := bigint.NewNatPlus(2)
// 	require.Equal(t, uint64(2), two.Uint64())
// 	twoTimesTo := two.Mul(two)
// 	require.Equal(t, uint64(4), twoTimesTo.Uint64())
// 	four := bigint.NewNatPlus(4)
// 	require.Equal(t, uint64(4), four.Uint64())
// 	require.True(t, four.Equal(twoTimesTo))
// }

// func BenchmarkMulWithArithmeticFromMixin(b *testing.B) {
// 	two := bigint.NewNatPlus(2)
// 	for range b.N {
// 		// bigint.NewNatPlus(2)
// 		two.Mul(two)
// 		// twoTimesTo := two.Mul(two)
// 		// four := bigint.NewNatPlus(4)
// 		// require.True(b, four.Equal(twoTimesTo))
// 	}
// }

// func BenchmarkMulWithArithmeticFromTheArithmeticObjectItself(b *testing.B) {
// 	two := bigint.NewNatPlus(2)
// 	arith := two.Arithmetic()
// 	for range b.N {
// 		// bigint.NewNatPlus(2)
// 		arith.Mul(two, two)
// 		// twoTimesTo := two.Mul(two)
// 		// four := bigint.NewNatPlus(4)
// 		// require.True(b, four.Equal(twoTimesTo))
// 	}
// }

// func BenchmarkMulWithNativeBigInt(b *testing.B) {
// 	two := new(big.Int).SetUint64(2)
// 	for range b.N {
// 		new(big.Int).Mul(two, two)
// 	}
// }

// func BenchmarkMulWithSaferithNat(b *testing.B) {
// 	two := new(saferith.Nat).SetUint64(2)
// 	for range b.N {
// 		new(saferith.Nat).Mul(two, two, -1)
// 	}
// }

// func BenchmarkExpWithArithmetic(b *testing.B) {
// 	two := bigint.NewNatPlus(2)
// 	four := bigint.NewNatPlus(4)
// 	arith := two.Arithmetic().WithBottomAtZeroAndModulus(four)
// 	for range b.N {
// 		// bigint.NewNatPlus(2)
// 		arith.Mod(two, four)
// 		// twoTimesTo := two.Mul(two)
// 		// four := bigint.NewNatPlus(4)
// 		// require.True(b, four.Equal(twoTimesTo))
// 	}
// }

// func BenchmarkExpWithNativeBigInt(b *testing.B) {
// 	two := new(big.Int).SetUint64(2)
// 	four := new(big.Int).SetUint64(4)
// 	for range b.N {
// 		new(big.Int).Exp(two, two, four)
// 	}
// }

// func BenchmarkExpWithSaferithNat(b *testing.B) {
// 	two := new(saferith.Nat).SetUint64(2)
// 	four := saferith.ModulusFromUint64(4)
// 	for range b.N {
// 		new(saferith.Nat).Exp(two, two, four)
// 	}
// }

// func RandomNatSize(prng io.Reader, bitSize int) (*saferith.Nat, error) {
// 	bound := new(saferith.Nat).Lsh(new(saferith.Nat).SetUint64(1), uint(bitSize), bitSize+1)
// 	resultBig, err := crand.Int(prng, bound.Big())
// 	if err != nil {
// 		return nil, errs.WrapRandomSample(err, "cannot sample big.Int")
// 	}

// 	return new(saferith.Nat).SetBig(resultBig, bitSize), nil
// }

// func Benchmark_ModExp(b *testing.B) {
// 	prng := crand.Reader
// 	p, q, err := primes.GeneratePrimePair(1024, prng)
// 	require.NoError(b, err)

// 	pq := new(saferith.Nat).Mul(p, q, -1)

// 	m := new(saferith.Nat).Mul(pq, pq, -1)
// 	mSafe := saferith.ModulusFromNat(m)
// 	mBig := m.Big()
// 	mArith := new(bigint.Nat).New(new(bigint.BigInt).New(mBig))

// 	exp, err := RandomNatSize(prng, 4096)
// 	require.NoError(b, err)
// 	expBig := exp.Big()
// 	expArith := new(bigint.Nat).New(new(bigint.BigInt).New(expBig))

// 	base, err := RandomNatSize(prng, 4096)
// 	require.NoError(b, err)

// 	baseBig := base.Big()
// 	baseArith := new(bigint.Nat).New(new(bigint.BigInt).New(baseBig))

// 	arith := baseArith.Arithmetic().WithBottomAtZeroAndModulus(mArith)
// 	require.Equal(b, arith.Type(), integer.ForZn)

// 	b.ResetTimer()
// 	b.Run("Arithmetic interface", func(b *testing.B) {
// 		for range b.N {
// 			arith.Mul(baseArith, expArith)
// 		}
// 	})
// 	b.Run("big int", func(b *testing.B) {
// 		for range b.N {
// 			new(big.Int).Mod(new(big.Int).Mul(baseBig, expBig), mBig)
// 		}
// 	})
// 	b.Run("saferith nat", func(b *testing.B) {
// 		for range b.N {
// 			new(saferith.Nat).ModMul(base, exp, mSafe)
// 		}
// 	})
// }
