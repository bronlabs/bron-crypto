package hashmap

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

type Key struct {
	value string
}
type Value any

func (k Key) Hash() [32]byte {
	return sha3.Sum256([]byte(k.value))
}

func TestPutAndGet(t *testing.T) {
	obj := NewHashMap[Key, string]()
	obj.Put(Key{value: "1"}, "1")
	obj.Put(Key{value: "2"}, "2")
	actual, found := obj.Get(Key{value: "1"})
	require.True(t, found)
	require.Equal(t, "1", actual)
}

func TestPutNilKey(t *testing.T) {
	obj := NewHashMap[Key, string]()
	obj.Put(nil, "1")
	require.Equal(t, 0, obj.Size())
}

func TestPutNilValue(t *testing.T) {
	// we allow nil values
	obj := NewHashMap[Key, Value]()
	obj.Put(Key{value: "1"}, nil)
	require.Equal(t, 1, obj.Size())
}

func TestPutConflict(t *testing.T) {
	obj := NewHashMap[Key, string]()
	obj.Put(Key{value: "1"}, "1")
	obj.Put(Key{value: "1"}, "2")
	actual, found := obj.Get(Key{value: "1"})
	require.True(t, found)
	require.Equal(t, "2", actual)
}

func TestSize(t *testing.T) {
	obj := NewHashMap[Key, string]()
	obj.Put(Key{value: "1"}, "1")
	obj.Put(Key{value: "2"}, "2")
	actual := obj.Size()
	require.Equal(t, 2, actual)
}

func TestContains(t *testing.T) {
	obj := NewHashMap[Key, string]()
	obj.Put(Key{value: "1"}, "1")
	obj.Put(Key{value: "2"}, "2")
	actual := obj.Contains(Key{value: "1"})
	require.True(t, actual)
	actual = obj.Contains(Key{value: "4"})
	require.False(t, actual)
}

func TestEmpty(t *testing.T) {
	obj := NewHashMap[Key, string]()
	require.True(t, obj.IsEmpty())
	obj.Put(Key{value: "1"}, "1")
	obj.Put(Key{value: "2"}, "2")
	require.False(t, obj.IsEmpty())
}

func TestRemove(t *testing.T) {
	obj := NewHashMap[Key, string]()
	require.True(t, obj.IsEmpty())
	obj.Put(Key{value: "1"}, "1")
	obj.Put(Key{value: "2"}, "2")
	obj.Remove(Key{value: "2"})
	_, found := obj.Get(Key{value: "2"})
	require.False(t, found)
}

func TestClear(t *testing.T) {
	obj := NewHashMap[Key, string]()
	require.True(t, obj.IsEmpty())
	obj.Put(Key{value: "1"}, "1")
	obj.Put(Key{value: "2"}, "2")
	obj.Clear()
	require.True(t, obj.IsEmpty())
}
