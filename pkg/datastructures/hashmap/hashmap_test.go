package hashmap

import (
	"crypto/sha256"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/stretchr/testify/require"
)

type Value struct {
	value string
}

func (k Value) HashCode() [32]byte {
	return sha256.Sum256([]byte(k.value))
}

func TestGet(t *testing.T) {
	testHashMap, err := NewHashmap[Value]([]Value{
		{value: "1"},
		{value: "2"},
	})
	require.NoError(t, err)
	actual, found := Get(testHashMap, Value{value: "1"})
	require.True(t, found)
	require.Equal(t, Value{value: "1"}, actual)
	_, found = Get(testHashMap, Value{value: "3"})
	require.False(t, found)
}

func TestPut(t *testing.T) {
	testHashMap, err := NewHashmap[Value]([]Value{})
	require.NoError(t, err)
	Put(testHashMap, Value{value: "1"})
	actual, found := Get(testHashMap, Value{value: "1"})
	require.True(t, found)
	require.Equal(t, Value{value: "1"}, actual)
}

func TestIsEmpty(t *testing.T) {
	testHashMap, err := NewHashmap[Value]([]Value{})
	require.NoError(t, err)
	empty := IsEmpty(testHashMap)
	require.True(t, empty)
	testHashMap = Put(testHashMap, Value{value: "1"})
	empty = IsEmpty(testHashMap)
	require.False(t, empty)
}

func TestContains(t *testing.T) {
	testHashMap, err := NewHashmap[Value]([]Value{
		{value: "1"},
	})
	require.NoError(t, err)
	actual := Contains(testHashMap, Value{value: "1"})
	require.True(t, actual)
	actual = Contains(testHashMap, Value{value: "2"})
	require.False(t, actual)
}

func TestAdd(t *testing.T) {
	testHashMap, err := NewHashmap[Value]([]Value{
		{value: "1"},
	})
	require.NoError(t, err)
	testHashMap, err = Add(testHashMap, Value{value: "2"})
	require.NoError(t, err)
	require.Equal(t, 2, Size(testHashMap))
	_, err = Add(testHashMap, Value{value: "2"})
	require.Equal(t, 2, Size(testHashMap))
	require.True(t, errs.IsDuplicate(err))
}
