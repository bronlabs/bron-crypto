package hashset

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

type Value struct {
	value string
}

func (k Value) Hash() [32]byte {
	return sha3.Sum256([]byte(k.value))
}

func TestGet(t *testing.T) {
	testHashMap, err := NewHashSet[Value]([]Value{
		{value: "1"},
		{value: "2"},
	})
	require.NoError(t, err)
	actual, found := testHashMap.Get(Value{value: "1"})
	require.True(t, found)
	require.Equal(t, Value{value: "1"}, actual)
	_, found = testHashMap.Get(Value{value: "3"})
	require.False(t, found)
}

func TestIsEmpty(t *testing.T) {
	testHashMap, err := NewHashSet[Value]([]Value{})
	require.NoError(t, err)
	empty := testHashMap.IsEmpty()
	require.True(t, empty)
	exist := testHashMap.Add(Value{value: "1"})
	require.False(t, exist)
	empty = testHashMap.IsEmpty()
	require.False(t, empty)
}

func TestContains(t *testing.T) {
	testHashMap, err := NewHashSet[Value]([]Value{
		{value: "1"},
	})
	require.NoError(t, err)
	actual := testHashMap.Contains(Value{value: "1"})
	require.True(t, actual)
	actual = testHashMap.Contains(Value{value: "2"})
	require.False(t, actual)
}

func TestAdd(t *testing.T) {
	testHashMap, err := NewHashSet[Value]([]Value{
		{value: "1"},
	})
	require.NoError(t, err)
	exist := testHashMap.Add(Value{value: "2"})
	require.False(t, exist)
	require.Equal(t, 2, testHashMap.Size())
	exist = testHashMap.Add(Value{value: "2"})
	require.Equal(t, 2, testHashMap.Size())
	require.True(t, exist)
}
