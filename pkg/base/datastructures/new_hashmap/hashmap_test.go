package newHashmap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type data struct {
	value uint64
}

func (d *data) HashCode() uint64 {
	return d.value % 10
}

func (d *data) Equals(rhs *data) bool {
	return d.value == rhs.value
}

var _ Hashable[*data] = (*data)(nil)

func Test_HashableHashMap(t *testing.T) {
	hashMap := NewHashableHashMap[*data, int]()

	// check empty map
	require.Zero(t, hashMap.Size())
	require.True(t, hashMap.IsEmpty())
	_, ok := hashMap.Get(&data{value: 348957})
	require.False(t, ok)
	ok = hashMap.ContainsKey(&data{value: 23465123})
	require.False(t, ok)

	// add two non-conflicting
	replaced, _ := hashMap.Put(&data{value: 1}, 1)
	require.False(t, replaced)
	replaced, _ = hashMap.Put(&data{value: 2}, 2)
	require.False(t, replaced)
	require.Equal(t, hashMap.Size(), 2)

	// add two conflicting
	replaced, _ = hashMap.Put(&data{value: 3}, 3)
	require.False(t, replaced)
	replaced, _ = hashMap.Put(&data{value: 33}, 33)
	require.False(t, replaced)
	require.Equal(t, hashMap.Size(), 4)

	// check exists
	require.True(t, hashMap.ContainsKey(&data{value: 1}))
	require.True(t, hashMap.ContainsKey(&data{value: 2}))
	require.True(t, hashMap.ContainsKey(&data{value: 3}))
	require.True(t, hashMap.ContainsKey(&data{value: 33}))
	require.False(t, hashMap.ContainsKey(&data{value: 43}))

	// check gets
	v1, ok := hashMap.Get(&data{value: 1})
	require.True(t, ok)
	require.Equal(t, v1, 1)
	v2, ok := hashMap.Get(&data{value: 2})
	require.True(t, ok)
	require.Equal(t, v2, 2)
	v3, ok := hashMap.Get(&data{value: 3})
	require.True(t, ok)
	require.Equal(t, v3, 3)
	v33, ok := hashMap.Get(&data{value: 33})
	require.True(t, ok)
	require.Equal(t, v33, 33)

	// check remove conflicting
	ok, removed := hashMap.Remove(&data{value: 3})
	require.True(t, ok)
	require.Equal(t, removed, 3)
	require.Equal(t, hashMap.Size(), 3)
	require.False(t, hashMap.ContainsKey(&data{value: 3}))
	require.True(t, hashMap.ContainsKey(&data{value: 33}))
	_, ok = hashMap.Get(&data{value: 3})
	require.False(t, ok)

	// remove again
	ok, _ = hashMap.Remove(&data{value: 3})
	require.False(t, ok)

	// remove non-conflicting
	ok, removed2 := hashMap.Remove(&data{value: 2})
	require.True(t, ok)
	require.Equal(t, removed2, 2)
	require.Equal(t, hashMap.Size(), 2)
	require.False(t, hashMap.ContainsKey(&data{value: 2}))
	_, ok = hashMap.Get(&data{value: 2})
	require.False(t, ok)

	// replace conflicting
	v33, ok = hashMap.Get(&data{value: 33})
	require.Equal(t, v33, 33)
	require.True(t, ok)
	replaced, oldValue := hashMap.Put(&data{value: 33}, 44)
	require.True(t, replaced)
	require.Equal(t, oldValue, 33)

	// replace non-conflicting
	hashMap.Put(&data{value: 7}, 7)
	replaced, d7 := hashMap.Put(&data{value: 7}, 777)
	require.True(t, replaced)
	require.Equal(t, d7, 7)

	// clear
	hashMap.Clear()
	require.Equal(t, hashMap.Size(), 0)
	require.True(t, hashMap.IsEmpty())
	_, ok = hashMap.Get(&data{value: 1})
	require.False(t, ok)
	_, ok = hashMap.Get(&data{value: 2})
	require.False(t, ok)
	_, ok = hashMap.Get(&data{value: 33})
	require.False(t, ok)
	_, ok = hashMap.Get(&data{value: 33})
	require.False(t, ok)
}

func Test_OrderedHashMap(t *testing.T) {
	hashMap := NewOrderedHashMap[int, int]()

	// check empty map
	require.Zero(t, hashMap.Size())
	require.True(t, hashMap.IsEmpty())
	_, ok := hashMap.Get(348957)
	require.False(t, ok)
	ok = hashMap.ContainsKey(23465123)
	require.False(t, ok)

	// add two non-conflicting
	replaced, _ := hashMap.Put(1, 1)
	require.False(t, replaced)
	replaced, _ = hashMap.Put(2, 2)
	require.False(t, replaced)
	require.Equal(t, hashMap.Size(), 2)

	// add two conflicting
	replaced, _ = hashMap.Put(3, 3)
	require.False(t, replaced)
	replaced, _ = hashMap.Put(33, 33)
	require.False(t, replaced)
	require.Equal(t, hashMap.Size(), 4)

	// check exists
	require.True(t, hashMap.ContainsKey(1))
	require.True(t, hashMap.ContainsKey(2))
	require.True(t, hashMap.ContainsKey(3))
	require.True(t, hashMap.ContainsKey(33))
	require.False(t, hashMap.ContainsKey(43))

	// check gets
	v1, ok := hashMap.Get(1)
	require.True(t, ok)
	require.Equal(t, v1, 1)
	v2, ok := hashMap.Get(2)
	require.True(t, ok)
	require.Equal(t, v2, 2)
	v3, ok := hashMap.Get(3)
	require.True(t, ok)
	require.Equal(t, v3, 3)
	v33, ok := hashMap.Get(33)
	require.True(t, ok)
	require.Equal(t, v33, 33)

	// check remove conflicting
	ok, removed := hashMap.Remove(3)
	require.True(t, ok)
	require.Equal(t, removed, 3)
	require.Equal(t, hashMap.Size(), 3)
	require.False(t, hashMap.ContainsKey(3))
	require.True(t, hashMap.ContainsKey(33))
	_, ok = hashMap.Get(3)
	require.False(t, ok)

	// remove again
	ok, _ = hashMap.Remove(3)
	require.False(t, ok)

	// remove non-conflicting
	ok, removed2 := hashMap.Remove(2)
	require.True(t, ok)
	require.Equal(t, removed2, 2)
	require.Equal(t, hashMap.Size(), 2)
	require.False(t, hashMap.ContainsKey(2))
	_, ok = hashMap.Get(2)
	require.False(t, ok)

	// replace conflicting
	v33, ok = hashMap.Get(33)
	require.Equal(t, v33, 33)
	require.True(t, ok)
	replaced, oldValue := hashMap.Put(33, 44)
	require.True(t, replaced)
	require.Equal(t, oldValue, 33)

	// replace non-conflicting
	hashMap.Put(7, 7)
	replaced, d7 := hashMap.Put(7, 777)
	require.True(t, replaced)
	require.Equal(t, d7, 7)

	// clear
	hashMap.Clear()
	require.Equal(t, hashMap.Size(), 0)
	require.True(t, hashMap.IsEmpty())
	_, ok = hashMap.Get(1)
	require.False(t, ok)
	_, ok = hashMap.Get(2)
	require.False(t, ok)
	_, ok = hashMap.Get(33)
	require.False(t, ok)
	_, ok = hashMap.Get(33)
	require.False(t, ok)
}
