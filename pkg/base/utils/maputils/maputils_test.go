package maputils_test

import (
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/utils/maputils"
)

func TestMapKeys(t *testing.T) {
	t.Parallel()
	input := map[int]string{
		1: "one",
		2: "two",
		3: "three",
	}

	result := maputils.MapKeys(input, func(k int) string {
		return strconv.Itoa(k)
	})

	expected := map[string]string{
		"1": "one",
		"2": "two",
		"3": "three",
	}
	require.Equal(t, expected, result)
}

func TestMapValues(t *testing.T) {
	t.Parallel()
	input := map[string]int{
		"one":   1,
		"two":   2,
		"three": 3,
	}

	result := maputils.MapValues(input, func(k string, v int) int {
		return v * 2
	})

	expected := map[string]int{
		"one":   2,
		"two":   4,
		"three": 6,
	}
	require.Equal(t, expected, result)
}

func TestJoinOrError(t *testing.T) {
	t.Parallel()

	// Test joining maps with no conflicts
	left := map[string]int{"a": 1, "b": 2}
	right := map[string]int{"c": 3, "d": 4}
	result, err := maputils.JoinOrError(left, right, func(k string, v1, v2 *int) (int, error) {
		return *v1 + *v2, nil
	})
	require.NoError(t, err)
	expected := map[string]int{"a": 1, "b": 2, "c": 3, "d": 4}
	require.Equal(t, expected, result)

	// Test joining maps with conflicts (sum values)
	left = map[string]int{"a": 1, "b": 2}
	right = map[string]int{"b": 3, "c": 4}
	result, err = maputils.JoinOrError(left, right, func(k string, v1, v2 *int) (int, error) {
		return *v1 + *v2, nil
	})
	require.NoError(t, err)
	expected = map[string]int{"a": 1, "b": 5, "c": 4}
	require.Equal(t, expected, result)

	// Test with error in dup function
	left = map[string]int{"a": 1, "b": 2}
	right = map[string]int{"b": 3, "c": 4}
	_, err = maputils.JoinOrError(left, right, func(k string, v1, v2 *int) (int, error) {
		return 0, errors.New("dup error")
	})
	require.Error(t, err)
}

func TestJoin(t *testing.T) {
	t.Parallel()

	// Test joining maps with no conflicts
	left := map[string]int{"a": 1, "b": 2}
	right := map[string]int{"c": 3, "d": 4}
	result := maputils.Join(left, right, func(k string, v1, v2 *int) int {
		return *v1 + *v2
	})
	expected := map[string]int{"a": 1, "b": 2, "c": 3, "d": 4}
	require.Equal(t, expected, result)

	// Test joining maps with conflicts (take right value)
	left = map[string]int{"a": 1, "b": 2}
	right = map[string]int{"b": 3, "c": 4}
	result = maputils.Join(left, right, func(k string, v1, v2 *int) int {
		return *v2
	})
	expected = map[string]int{"a": 1, "b": 3, "c": 4}
	require.Equal(t, expected, result)

	// Test joining maps with conflicts (sum values)
	left = map[string]int{"a": 1, "b": 2}
	right = map[string]int{"b": 3, "c": 4}
	result = maputils.Join(left, right, func(k string, v1, v2 *int) int {
		return *v1 + *v2
	})
	expected = map[string]int{"a": 1, "b": 5, "c": 4}
	require.Equal(t, expected, result)
}

func TestIsSubMap(t *testing.T) {
	t.Parallel()

	eq := func(a, b int) bool { return a == b }

	// Test when sub is a submap
	sub := map[string]int{"a": 1, "b": 2}
	super := map[string]int{"a": 1, "b": 2, "c": 3}
	require.True(t, maputils.IsSubMap(sub, super, eq))

	// Test when sub equals super
	sub = map[string]int{"a": 1, "b": 2}
	super = map[string]int{"a": 1, "b": 2}
	require.True(t, maputils.IsSubMap(sub, super, eq))

	// Test when sub has a key not in super
	sub = map[string]int{"a": 1, "d": 4}
	super = map[string]int{"a": 1, "b": 2, "c": 3}
	require.False(t, maputils.IsSubMap(sub, super, eq))

	// Test when sub has a different value for same key
	sub = map[string]int{"a": 1, "b": 99}
	super = map[string]int{"a": 1, "b": 2, "c": 3}
	require.False(t, maputils.IsSubMap(sub, super, eq))

	// Test when sub is larger than super
	sub = map[string]int{"a": 1, "b": 2, "c": 3, "d": 4}
	super = map[string]int{"a": 1, "b": 2}
	require.False(t, maputils.IsSubMap(sub, super, eq))

	// Test empty sub map
	sub = map[string]int{}
	super = map[string]int{"a": 1, "b": 2}
	require.True(t, maputils.IsSubMap(sub, super, eq))
}
