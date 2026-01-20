package hashmap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
)

// CollidingKey is a test type where we can control the hash code to force collisions
type CollidingKey struct {
	ID   int
	Hash base.HashCode
}

func (k *CollidingKey) Equal(other *CollidingKey) bool {
	return k.ID == other.ID
}

func (k *CollidingKey) HashCode() base.HashCode {
	return k.Hash
}

func TestHashableMap_TryPut_HashCollision(t *testing.T) {
	t.Parallel()

	m := hashmap.NewHashable[*CollidingKey, string]()

	// Create two keys with the same hash but different IDs (not Equal)
	sameHash := base.HashCode(42)
	key1 := &CollidingKey{ID: 1, Hash: sameHash}
	key2 := &CollidingKey{ID: 2, Hash: sameHash}

	// Verify they have the same hash but are not equal
	require.Equal(t, key1.HashCode(), key2.HashCode(), "keys should have same hash")
	require.False(t, key1.Equal(key2), "keys should not be equal")

	// Put first key
	replaced1, oldVal1 := m.TryPut(key1, "value1")
	require.False(t, replaced1, "first put should not replace")
	require.Empty(t, oldVal1, "first put should have no old value")

	// Put second key (same hash, different key)
	replaced2, oldVal2 := m.TryPut(key2, "value2")
	require.False(t, replaced2, "second put should not replace (different key)")
	require.Empty(t, oldVal2, "second put should have no old value")

	// Both keys should exist with their respective values
	got1, exists1 := m.Get(key1)
	require.True(t, exists1, "key1 should exist")
	require.Equal(t, "value1", got1)

	got2, exists2 := m.Get(key2)
	require.True(t, exists2, "key2 should exist")
	require.Equal(t, "value2", got2)

	// Size should be 2
	require.Equal(t, 2, m.Size())

	// Update key1 - should replace
	replaced3, oldVal3 := m.TryPut(key1, "value1-updated")
	require.True(t, replaced3, "updating key1 should replace")
	require.Equal(t, "value1", oldVal3, "old value should be returned")

	// key1 should have new value, key2 unchanged
	got1Updated, _ := m.Get(key1)
	require.Equal(t, "value1-updated", got1Updated)

	got2Unchanged, _ := m.Get(key2)
	require.Equal(t, "value2", got2Unchanged)

	// Size should still be 2
	require.Equal(t, 2, m.Size())
}

func TestHashableMap_TryRemove_HashCollision(t *testing.T) {
	t.Parallel()

	m := hashmap.NewHashable[*CollidingKey, string]()

	// Create three keys with the same hash
	sameHash := base.HashCode(42)
	key1 := &CollidingKey{ID: 1, Hash: sameHash}
	key2 := &CollidingKey{ID: 2, Hash: sameHash}
	key3 := &CollidingKey{ID: 3, Hash: sameHash}

	m.Put(key1, "value1")
	m.Put(key2, "value2")
	m.Put(key3, "value3")
	require.Equal(t, 3, m.Size())

	// Remove middle key
	removed, oldVal := m.TryRemove(key2)
	require.True(t, removed)
	require.Equal(t, "value2", oldVal)
	require.Equal(t, 2, m.Size())

	// key2 should not exist, others should
	_, exists2 := m.Get(key2)
	require.False(t, exists2, "key2 should be removed")

	got1, exists1 := m.Get(key1)
	require.True(t, exists1, "key1 should still exist")
	require.Equal(t, "value1", got1)

	got3, exists3 := m.Get(key3)
	require.True(t, exists3, "key3 should still exist")
	require.Equal(t, "value3", got3)

	// Try to remove non-existent key with same hash
	key4 := &CollidingKey{ID: 4, Hash: sameHash}
	removed4, _ := m.TryRemove(key4)
	require.False(t, removed4, "removing non-existent key should return false")
	require.Equal(t, 2, m.Size())
}
