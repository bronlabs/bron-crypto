package maputils

func MapValues[K comparable, VIn, VOut any](input map[K]VIn, f func(K, VIn) VOut) map[K]VOut {
	out := make(map[K]VOut)
	for k, v := range input {
		out[k] = f(k, v)
	}
	return out
}

func Join[K comparable, VLIn, VRIn, VOut any](left map[K]VLIn, right map[K]VRIn, f func(K, VLIn, VRIn) VOut) map[K]VOut {
	out := make(map[K]VOut)
	for k, l := range left {
		if r, ok := right[k]; ok {
			out[k] = f(k, l, r)
		}
	}
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
