package testutils2

import (
	"reflect"
	"strconv"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"golang.org/x/exp/constraints"
)

var _ ObjectAdapter[int] = (*IntegerAdapter[int])(nil)

type IntegerAdapter[T constraints.Integer] struct{}

func (a *IntegerAdapter[T]) Wrap(x UnderlyingGenerator) T {
	var out T
	mod := UnderlyingGenerator(reflect.TypeOf(out).Size())
	return T(x % mod)
}

func (a *IntegerAdapter[T]) Unwrap(x T) UnderlyingGenerator {
	return UnderlyingGenerator(x)
}

func (a *IntegerAdapter[T]) Zero() T {
	return T(0)
}

func (a *IntegerAdapter[T]) IsZero(x T) bool {
	return x == 0
}

var _ ObjectAdapter[string] = (*StringAdapter[string])(nil)

type StringAdapter[T ~string] struct{}

func (a *StringAdapter[T]) Wrap(x UnderlyingGenerator) T {
	return T(strconv.Itoa(int(x)))
}

func (a *StringAdapter[T]) Unwrap(x T) UnderlyingGenerator {
	i, err := strconv.Atoi(string(x))
	if err != nil {
		panic(errs.WrapFailed(err, "could not unwrap %s", x))
	}
	return UnderlyingGenerator(i)
}

func (a *StringAdapter[T]) Zero() T {
	return T("")
}

func (a *StringAdapter[T]) IsZero(x T) bool {
	return x == ""
}

var _ ObjectAdapter[byte] = (*ByteAdapter[byte])(nil)

type ByteAdapter[T ~byte] struct{}

func (a *ByteAdapter[T]) Wrap(x UnderlyingGenerator) T {
	return T(x % 8)
}

func (a *ByteAdapter[T]) Unwrap(x T) UnderlyingGenerator {
	return UnderlyingGenerator(x)
}

func (a *ByteAdapter[T]) Zero() T {
	return T(byte(0))
}

func (a *ByteAdapter[T]) IsZero(x T) bool {
	return x == 0
}

var _ CollectionAdapter[[]any, any] = (*SliceAdapter[[]any, any])(nil)

type SliceAdapter[S ~[]O, O Object] struct {
	objectAdapter ObjectAdapter[O]
}

func (a *SliceAdapter[S, O]) Wrap(xs []UnderlyingGenerator) S {
	out := make(S, len(xs))
	for i, x := range xs {
		out[i] = a.objectAdapter.Wrap(x)
	}
	return out
}
func (a *SliceAdapter[S, O]) Unwrap(xs S) []UnderlyingGenerator {
	out := make([]UnderlyingGenerator, len(xs))
	for i, x := range xs {
		out[i] = a.objectAdapter.Unwrap(x)
	}
	return out
}
func (a *SliceAdapter[S, O]) Zero() S {
	return make(S, 0)
}
func (a *SliceAdapter[S, O]) IsZero(xs S) bool {
	for _, x := range xs {
		if !a.objectAdapter.IsZero(x) {
			return false
		}
	}
	return true
}

var _ MapAdapter[map[int]any, int, any] = (*NativeMapAdapter[map[int]any, int, any])(nil)

type NativeMapAdapter[M ~map[K]V, K comparable, V Object] struct {
	keys   ObjectAdapter[K]
	values ObjectAdapter[V]
}

func (a *NativeMapAdapter[M, K, V]) Wrap(m map[UnderlyingGenerator]UnderlyingGenerator) M {
	out := map[K]V{}
	for uk, uv := range m {
		k := a.keys.Wrap(uk)
		v := a.values.Wrap(uv)
		out[k] = v
	}
	return out
}

func (a *NativeMapAdapter[M, K, V]) Unwrap(m M) map[UnderlyingGenerator]UnderlyingGenerator {
	out := map[UnderlyingGenerator]UnderlyingGenerator{}
	for k, v := range m {
		uk := a.keys.Unwrap(k)
		uv := a.values.Unwrap(v)
		out[uk] = uv
	}
	return out
}

func (a *NativeMapAdapter[M, K, V]) Zero() M {
	return map[K]V{}
}

func (a *NativeMapAdapter[M, K, V]) IsZero(m M) bool {
	return len(m) == 0
}
