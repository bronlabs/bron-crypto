package maputils

import "maps"

// MapKeys applies the given function to each key of the input map and returns a new map with the transformed keys and original values.
func MapKeys[KIn, KOut comparable, V any](input map[KIn]V, f func(KIn) KOut) map[KOut]V {
	out := make(map[KOut]V)
	for k, v := range input {
		out[f(k)] = v
	}
	return out
}

// MapValues applies the given function to each value of the input map and returns a new map with the original keys and transformed values.
func MapValues[K comparable, VIn, VOut any](input map[K]VIn, f func(K, VIn) VOut) map[K]VOut {
	out := make(map[K]VOut)
	for k, v := range input {
		out[k] = f(k, v)
	}
	return out
}

// JoinOrError merges two maps into one. If a key exists in both maps, the provided duplication function is called to resolve the conflict.
func JoinOrError[K comparable, V any](left, right map[K]V, dup func(K, *V, *V) (V, error)) (map[K]V, error) {
	out := maps.Clone(left)
	var err error
	for k, v := range right {
		if existing, exists := out[k]; exists {
			if out[k], err = dup(k, &existing, &v); err != nil {
				return nil, err
			}
		} else {
			out[k] = v
		}
	}
	return out, nil
}

// Join merges two maps into one. If a key exists in both maps, the provided duplication function is called to resolve the conflict.
func Join[K comparable, V any](left, right map[K]V, dup func(K, *V, *V) V) map[K]V {
	out, _ := JoinOrError(left, right, func(k K, v1, v2 *V) (V, error) {
		return dup(k, v1, v2), nil
	})
	return out
}

// IsSubMap checks if the 'sub' map is a submap of the 'super' map using the provided equality function for values.
func IsSubMap[K comparable, V any](sub, super map[K]V, eq func(a, b V) bool) bool {
	if len(sub) > len(super) {
		return false
	}
	for k, v := range sub {
		if sv, exists := super[k]; !exists || !eq(v, sv) {
			return false
		}
	}
	return true
}
