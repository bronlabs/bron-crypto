package maputils

import "maps"

func MapValues[K comparable, VIn, VOut any](input map[K]VIn, f func(K, VIn) VOut) map[K]VOut {
	out := make(map[K]VOut)
	for k, v := range input {
		out[k] = f(k, v)
	}
	return out
}

func JoinError[K comparable, V any](left, right map[K]V, dup func(K, *V, *V) (V, error)) (map[K]V, error) {
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

func Join[K comparable, V any](left, right map[K]V, dup func(K, *V, *V) V) map[K]V {
	out, _ := JoinError(left, right, func(k K, v1, v2 *V) (V, error) {
		return dup(k, v1, v2), nil
	})
	return out
}

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
