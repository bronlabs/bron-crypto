package testutils2

import (
	"reflect"
	"strconv"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"golang.org/x/exp/constraints"
)

var _ ObjectAdapter[int] = (*IntegerAdapter[int])(nil)

type IntegerAdapter[T constraints.Integer] struct{}

func (a *IntegerAdapter[T]) Wrap(x ObjectUnderlyer) T {
	var out T
	mod := ObjectUnderlyer(reflect.TypeOf(out).Size())
	return T(x % mod)
}

func (a *IntegerAdapter[T]) Unwrap(x T) ObjectUnderlyer {
	return ObjectUnderlyer(x)
}

func (a *IntegerAdapter[T]) ZeroValue() T {
	return T(0)
}

var _ ObjectAdapter[string] = (*StringAdapter[string])(nil)

type StringAdapter[T ~string] struct{}

func (a *StringAdapter[T]) Wrap(x ObjectUnderlyer) T {
	return T(strconv.Itoa(int(x)))
}

func (a *StringAdapter[T]) Unwrap(x T) ObjectUnderlyer {
	i, err := strconv.Atoi(string(x))
	if err != nil {
		panic(errs.WrapFailed(err, "could not unwrap %s", x))
	}
	return ObjectUnderlyer(i)
}

func (a *StringAdapter[T]) ZeroValue() T {
	return T("")
}

var _ ObjectAdapter[byte] = (*ByteAdapter[byte])(nil)

type ByteAdapter[T ~byte] struct{}

func (a *ByteAdapter[T]) Wrap(x ObjectUnderlyer) T {
	return T(x % 8)
}

func (a *ByteAdapter[T]) Unwrap(x T) ObjectUnderlyer {
	return ObjectUnderlyer(x)
}

func (a *ByteAdapter[T]) ZeroValue() T {
	return T(byte(0))
}

var _ CollectionAdapter[[]any, any] = (*SliceAdapter[[]any, any])(nil)

type SliceAdapter[S ~[]O, O Object] struct {
	objectAdapter ObjectAdapter[O]
}

func (a *SliceAdapter[S, O]) Wrap(xs CollectionUnderlyer) S {
	out := make(S, len(xs))
	for i, x := range xs {
		out[i] = a.objectAdapter.Wrap(x)
	}
	return out
}
func (a *SliceAdapter[S, O]) Unwrap(xs S) CollectionUnderlyer {
	out := make([]ObjectUnderlyer, len(xs))
	for i, x := range xs {
		out[i] = a.objectAdapter.Unwrap(x)
	}
	return out
}
func (a *SliceAdapter[S, O]) ZeroValue() S {
	return make(S, 0)
}

var _ MapAdapter[map[int]any, int, any] = (*NativeMapAdapter[map[int]any, int, any])(nil)

type NativeMapAdapter[M ~map[K]V, K comparable, V Object] struct {
	keys   ObjectAdapter[K]
	values ObjectAdapter[V]
}

func (a *NativeMapAdapter[M, K, V]) Wrap(m MapUnderlyer) M {
	out := map[K]V{}
	for uk, uv := range m {
		k := a.keys.Wrap(uk)
		v := a.values.Wrap(uv)
		out[k] = v
	}
	return out
}

func (a *NativeMapAdapter[M, K, V]) Unwrap(m M) MapUnderlyer {
	out := map[ObjectUnderlyer]ObjectUnderlyer{}
	for k, v := range m {
		uk := a.keys.Unwrap(k)
		uv := a.values.Unwrap(v)
		out[uk] = uv
	}
	return out
}

func (a *NativeMapAdapter[M, K, V]) ZeroValue() M {
	return map[K]V{}
}
