package fuzzutils

//func RunCollectionPropertyTest[C Collection[O], O Object](f *testing.F, seedCorpus [][2]uint64, checkInvariants func(*testing.T, CollectionGenerator[C, O]), generators ...CollectionGenerator[C, O]) {
//	f.Helper()
//	require.GreaterOrEqual(f, len(generators), 1)
//	for _, g := range generators {
//		require.NotNil(f, g)
//	}
//	f.Add(uint64(0), uint64(0)) // this is to shut off the warning
//	for _, seedPair := range seedCorpus {
//		f.Add(seedPair[0], seedPair[1])
//	}
//	f.Fuzz(func(t *testing.T, seed1, seed2 uint64) {
//		for i, generator := range generators {
//			t.Run(fmt.Sprintf("generator=%d", i), func(t *testing.T) {
//				t.Helper()
//				g := generator.Clone()
//				g.Reseed(seed1, seed2)
//				checkInvariants(t, g)
//			})
//		}
//	})
//}
