package iterutils_test

import (
	"errors"
	"iter"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
)

// Helper to create iter.Seq from slice
func seqFromSlice[V any](s []V) iter.Seq[V] {
	return func(yield func(V) bool) {
		for _, v := range s {
			if !yield(v) {
				return
			}
		}
	}
}

// Helper to create iter.Seq2 from map
func seq2FromMap[K comparable, V any](m map[K]V) iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for k, v := range m {
			if !yield(k, v) {
				return
			}
		}
	}
}

func TestContains(t *testing.T) {
	t.Parallel()
	seq := seqFromSlice([]int{1, 2, 3, 4, 5})
	require.True(t, iterutils.Contains(seq, 3))

	seq = seqFromSlice([]int{1, 2, 3, 4, 5})
	require.False(t, iterutils.Contains(seq, 10))
}

func TestContains2(t *testing.T) {
	t.Parallel()
	m := map[string]int{"a": 1, "b": 2, "c": 3}
	seq := seq2FromMap(m)
	require.True(t, iterutils.Contains2(seq, "b", 2))

	seq = seq2FromMap(m)
	require.False(t, iterutils.Contains2(seq, "b", 99))
}

func TestContainsFunc(t *testing.T) {
	t.Parallel()
	seq := seqFromSlice([]int{1, 2, 3, 4, 5})
	eq := func(a, b int) bool { return a == b }
	require.True(t, iterutils.ContainsFunc(seq, 3, eq))

	seq = seqFromSlice([]int{1, 2, 3, 4, 5})
	require.False(t, iterutils.ContainsFunc(seq, 10, eq))
}

func TestContainsFunc2(t *testing.T) {
	t.Parallel()
	m := map[string]int{"a": 1, "b": 2, "c": 3}
	seq := seq2FromMap(m)
	eq := func(k1 string, v1 int, k2 string, v2 int) bool {
		return k1 == k2 && v1 == v2
	}
	require.True(t, iterutils.ContainsFunc2(seq, "b", 2, eq))

	seq = seq2FromMap(m)
	require.False(t, iterutils.ContainsFunc2(seq, "b", 99, eq))
}

func TestEmpty(t *testing.T) {
	t.Parallel()
	seq := iterutils.Empty[int]()
	result := slices.Collect(seq)
	require.Empty(t, result)
}

func TestEmpty2(t *testing.T) {
	t.Parallel()
	seq := iterutils.Empty2[string, int]()
	count := 0
	for range seq {
		count++
	}
	require.Equal(t, 0, count)
}

func TestMap(t *testing.T) {
	t.Parallel()
	seq := seqFromSlice([]int{1, 2, 3})
	mapped := iterutils.Map(seq, func(x int) int { return x * 2 })
	result := slices.Collect(mapped)
	require.Equal(t, []int{2, 4, 6}, result)
}

func TestMap2(t *testing.T) {
	t.Parallel()
	m := map[string]int{"a": 1, "b": 2}
	seq := seq2FromMap(m)
	mapped := iterutils.Map2(seq, func(k string, v int) (string, int) {
		return k + k, v * 2
	})
	result := make(map[string]int)
	for k, v := range mapped {
		result[k] = v
	}
	require.Equal(t, map[string]int{"aa": 2, "bb": 4}, result)
}

func TestMapKeys2(t *testing.T) {
	t.Parallel()
	m := map[string]int{"a": 1, "b": 2}
	seq := seq2FromMap(m)
	mapped := iterutils.MapKeys2(seq, func(k string, v int) string {
		return k + k
	})
	result := make(map[string]int)
	for k, v := range mapped {
		result[k] = v
	}
	require.Equal(t, map[string]int{"aa": 1, "bb": 2}, result)
}

func TestMapValues2(t *testing.T) {
	t.Parallel()
	m := map[string]int{"a": 1, "b": 2}
	seq := seq2FromMap(m)
	mapped := iterutils.MapValues2(seq, func(k string, v int) int {
		return v * 2
	})
	result := make(map[string]int)
	for k, v := range mapped {
		result[k] = v
	}
	require.Equal(t, map[string]int{"a": 2, "b": 4}, result)
}

func TestConcat(t *testing.T) {
	t.Parallel()
	seq1 := seqFromSlice([]int{1, 2})
	seq2 := seqFromSlice([]int{3, 4})
	seq3 := seqFromSlice([]int{5})
	concatenated := iterutils.Concat(seq1, seq2, seq3)
	result := slices.Collect(concatenated)
	require.Equal(t, []int{1, 2, 3, 4, 5}, result)
}

func TestConcat2(t *testing.T) {
	t.Parallel()
	m1 := map[string]int{"a": 1}
	m2 := map[string]int{"b": 2}
	seq1 := seq2FromMap(m1)
	seq2 := seq2FromMap(m2)
	concatenated := iterutils.Concat2(seq1, seq2)
	result := make(map[string]int)
	for k, v := range concatenated {
		result[k] = v
	}
	require.Equal(t, map[string]int{"a": 1, "b": 2}, result)
}

func TestFlatten(t *testing.T) {
	t.Parallel()
	inner1 := seqFromSlice([]int{1, 2})
	inner2 := seqFromSlice([]int{3, 4})
	outer := seqFromSlice([]iter.Seq[int]{inner1, inner2})
	flattened := iterutils.Flatten(outer)
	result := slices.Collect(flattened)
	require.Equal(t, []int{1, 2, 3, 4}, result)
}

func TestFlatten2(t *testing.T) {
	t.Parallel()
	m1 := map[string]int{"a": 1}
	m2 := map[string]int{"b": 2}
	inner1 := seq2FromMap(m1)
	inner2 := seq2FromMap(m2)
	outer := seqFromSlice([]iter.Seq2[string, int]{inner1, inner2})
	flattened := iterutils.Flatten2(outer)
	result := make(map[string]int)
	for k, v := range flattened {
		result[k] = v
	}
	require.Equal(t, map[string]int{"a": 1, "b": 2}, result)
}

func TestAny(t *testing.T) {
	t.Parallel()
	seq := seqFromSlice([]int{1, 2, 3, 4, 5})
	require.True(t, iterutils.Any(seq, func(x int) bool { return x == 3 }))

	seq = seqFromSlice([]int{1, 2, 3, 4, 5})
	require.False(t, iterutils.Any(seq, func(x int) bool { return x > 10 }))
}

func TestAny2(t *testing.T) {
	t.Parallel()
	m := map[string]int{"a": 1, "b": 2, "c": 3}
	seq := seq2FromMap(m)
	require.True(t, iterutils.Any2(seq, func(k string, v int) bool { return v == 2 }))

	seq = seq2FromMap(m)
	require.False(t, iterutils.Any2(seq, func(k string, v int) bool { return v > 10 }))
}

func TestAll(t *testing.T) {
	t.Parallel()
	seq := seqFromSlice([]int{2, 4, 6})
	require.True(t, iterutils.All(seq, func(x int) bool { return x%2 == 0 }))

	seq = seqFromSlice([]int{1, 2, 3})
	require.False(t, iterutils.All(seq, func(x int) bool { return x%2 == 0 }))
}

func TestAll2(t *testing.T) {
	t.Parallel()
	m := map[string]int{"a": 2, "b": 4}
	seq := seq2FromMap(m)
	require.True(t, iterutils.All2(seq, func(k string, v int) bool { return v%2 == 0 }))

	m = map[string]int{"a": 1, "b": 2}
	seq = seq2FromMap(m)
	require.False(t, iterutils.All2(seq, func(k string, v int) bool { return v%2 == 0 }))
}

func TestEqual(t *testing.T) {
	t.Parallel()
	seq1 := seqFromSlice([]int{1, 2, 3})
	seq2 := seqFromSlice([]int{1, 2, 3})
	require.True(t, iterutils.Equal(seq1, seq2))

	seq1 = seqFromSlice([]int{1, 2, 3})
	seq2 = seqFromSlice([]int{1, 2, 4})
	require.False(t, iterutils.Equal(seq1, seq2))
}

func TestEqual2(t *testing.T) {
	t.Parallel()
	// Create deterministic sequences by using slices
	seq1 := func(yield func(string, int) bool) {
		pairs := [][2]any{{"a", 1}, {"b", 2}}
		for _, p := range pairs {
			if !yield(p[0].(string), p[1].(int)) {
				return
			}
		}
	}
	seq2 := func(yield func(string, int) bool) {
		pairs := [][2]any{{"a", 1}, {"b", 2}}
		for _, p := range pairs {
			if !yield(p[0].(string), p[1].(int)) {
				return
			}
		}
	}
	require.True(t, iterutils.Equal2(seq1, seq2))
}

func TestEqualFunc(t *testing.T) {
	t.Parallel()
	seq1 := seqFromSlice([]int{1, 2, 3})
	seq2 := seqFromSlice([]int{1, 2, 3})
	eq := func(a, b int) bool { return a == b }
	require.True(t, iterutils.EqualFunc(seq1, seq2, eq))

	seq1 = seqFromSlice([]int{1, 2, 3})
	seq2 = seqFromSlice([]int{1, 2, 4})
	require.False(t, iterutils.EqualFunc(seq1, seq2, eq))
}

func TestEqualFunc2(t *testing.T) {
	t.Parallel()
	seq1 := func(yield func(string, int) bool) {
		pairs := [][2]any{{"a", 1}, {"b", 2}}
		for _, p := range pairs {
			if !yield(p[0].(string), p[1].(int)) {
				return
			}
		}
	}
	seq2 := func(yield func(string, int) bool) {
		pairs := [][2]any{{"a", 1}, {"b", 2}}
		for _, p := range pairs {
			if !yield(p[0].(string), p[1].(int)) {
				return
			}
		}
	}
	eq := func(k1 string, v1 int, k2 string, v2 int) bool {
		return k1 == k2 && v1 == v2
	}
	require.True(t, iterutils.EqualFunc2(seq1, seq2, eq))
}

func TestFilter(t *testing.T) {
	t.Parallel()
	seq := seqFromSlice([]int{1, 2, 3, 4, 5})
	filtered := iterutils.Filter(seq, func(x int) bool { return x%2 == 0 })
	result := slices.Collect(filtered)
	require.Equal(t, []int{2, 4}, result)
}

func TestFilter2(t *testing.T) {
	t.Parallel()
	m := map[string]int{"a": 1, "b": 2, "c": 3, "d": 4}
	seq := seq2FromMap(m)
	filtered := iterutils.Filter2(seq, func(k string, v int) bool { return v%2 == 0 })
	result := make(map[string]int)
	for k, v := range filtered {
		result[k] = v
	}
	require.Equal(t, map[string]int{"b": 2, "d": 4}, result)
}

func TestTruncate(t *testing.T) {
	t.Parallel()
	seq := seqFromSlice([]int{1, 2, 3, 4, 5})
	truncated := iterutils.Truncate(seq, 3)
	result := slices.Collect(truncated)
	require.Equal(t, []int{1, 2, 3}, result)

	// Test with n <= 0
	seq = seqFromSlice([]int{1, 2, 3})
	truncated = iterutils.Truncate(seq, 0)
	result = slices.Collect(truncated)
	require.Empty(t, result)
}

func TestTruncate2(t *testing.T) {
	t.Parallel()
	seq := func(yield func(string, int) bool) {
		pairs := [][2]any{{"a", 1}, {"b", 2}, {"c", 3}}
		for _, p := range pairs {
			if !yield(p[0].(string), p[1].(int)) {
				return
			}
		}
	}
	truncated := iterutils.Truncate2(seq, 2)
	count := 0
	for range truncated {
		count++
	}
	require.Equal(t, 2, count)

	// Test with n <= 0
	truncated = iterutils.Truncate2(seq, 0)
	count = 0
	for range truncated {
		count++
	}
	require.Equal(t, 0, count)
}

func TestReduce(t *testing.T) {
	t.Parallel()
	seq := seqFromSlice([]int{1, 2, 3, 4})
	result := iterutils.Reduce(seq, 0, func(acc, x int) int {
		return acc + x
	})
	require.Equal(t, 10, result)
}

func TestReduce2(t *testing.T) {
	t.Parallel()
	m := map[string]int{"a": 1, "b": 2, "c": 3}
	seq := seq2FromMap(m)
	result := iterutils.Reduce2(seq, 0, func(acc int, k string, v int) int {
		return acc + v
	})
	require.Equal(t, 6, result)
}

func TestReduceOrError(t *testing.T) {
	t.Parallel()
	// Test successful reduce
	seq := seqFromSlice([]int{1, 2, 3, 4})
	result, err := iterutils.ReduceOrError(seq, 0, func(acc, x int) (int, error) {
		return acc + x, nil
	})
	require.NoError(t, err)
	require.Equal(t, 10, result)

	// Test with error
	seq = seqFromSlice([]int{1, 2, 3, 4})
	_, err = iterutils.ReduceOrError(seq, 0, func(acc, x int) (int, error) {
		if x == 3 {
			return 0, errors.New("error at 3")
		}
		return acc + x, nil
	})
	require.Error(t, err)
}

func TestReduceOrError2(t *testing.T) {
	t.Parallel()
	// Test successful reduce
	m := map[string]int{"a": 1, "b": 2}
	seq := seq2FromMap(m)
	result, err := iterutils.ReduceOrError2(seq, 0, func(acc int, k string, v int) (int, error) {
		return acc + v, nil
	})
	require.NoError(t, err)
	require.Equal(t, 3, result)

	// Test with error
	seq = seq2FromMap(m)
	_, err = iterutils.ReduceOrError2(seq, 0, func(acc int, k string, v int) (int, error) {
		if v == 2 {
			return 0, errors.New("error at 2")
		}
		return acc + v, nil
	})
	require.Error(t, err)
}

func TestZipTruncate(t *testing.T) {
	t.Parallel()
	seq1 := seqFromSlice([]int{1, 2, 3})
	seq2 := seqFromSlice([]string{"a", "b"})
	zipped := iterutils.ZipTruncate(seq1, seq2)
	result := make(map[int]string)
	for k, v := range zipped {
		result[k] = v
	}
	require.Equal(t, map[int]string{1: "a", 2: "b"}, result)
}

func TestZip(t *testing.T) {
	t.Parallel()
	// Test equal length sequences
	seq1 := seqFromSlice([]int{1, 2, 3})
	seq2 := seqFromSlice([]string{"a", "b", "c"})
	zipped := iterutils.Zip(seq1, seq2)
	result := slices.Collect(zipped)
	require.Len(t, result, 3)
	require.True(t, result[0].Ok1 && result[0].Ok2)
	require.Equal(t, 1, result[0].V1)
	require.Equal(t, "a", result[0].V2)

	// Test first sequence longer
	seq1 = seqFromSlice([]int{1, 2, 3})
	seq2 = seqFromSlice([]string{"a"})
	zipped = iterutils.Zip(seq1, seq2)
	result = slices.Collect(zipped)
	require.Len(t, result, 3)
	require.False(t, result[2].Ok2)
}

func TestZip2(t *testing.T) {
	t.Parallel()
	seq1 := func(yield func(string, int) bool) {
		pairs := [][2]any{{"a", 1}, {"b", 2}}
		for _, p := range pairs {
			if !yield(p[0].(string), p[1].(int)) {
				return
			}
		}
	}
	seq2 := func(yield func(string, int) bool) {
		pairs := [][2]any{{"x", 10}}
		for _, p := range pairs {
			if !yield(p[0].(string), p[1].(int)) {
				return
			}
		}
	}
	zipped := iterutils.Zip2(seq1, seq2)
	result := slices.Collect(zipped)
	require.Len(t, result, 2)
	require.True(t, result[0].Ok1 && result[0].Ok2)
	require.False(t, result[1].Ok2)
}
