package iterutils

import (
	"iter"
)

func Contains[In comparable](seq iter.Seq[In], v In) bool {
	for v2 := range seq {
		if v == v2 {
			return true
		}
	}

	return false
}

func ContainsFunc[In any](seq iter.Seq[In], v In, f func(In, In) bool) bool {
	for v2 := range seq {
		if f(v, v2) {
			return true
		}
	}

	return false
}

func Empty[V any]() iter.Seq[V] {
	return func(yield func(V) bool) {
		// Do nothing, effectively yielding no values.
	}
}

func Empty2[K, V any]() iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		// Do nothing, effectively yielding no key-value pairs.
	}
}

func Map[In, Out any](seq iter.Seq[In], f func(In) Out) iter.Seq[Out] {
	return func(yield func(Out) bool) {
		for in := range seq {
			if !yield(f(in)) {
				return
			}
		}
	}
}

func Map2[KIn, KOut, VIn, VOut any](seq iter.Seq2[KIn, VIn], f func(KIn, VIn) (KOut, VOut)) iter.Seq2[KOut, VOut] {
	return func(yield func(KOut, VOut) bool) {
		for k, v := range seq {
			if !yield(f(k, v)) {
				return
			}
		}
	}
}

func MapKeys2[KIn, KOut, V any](seq iter.Seq2[KIn, V], f func(KIn, V) KOut) iter.Seq2[KOut, V] {
	return func(yield func(KOut, V) bool) {
		for k, v := range seq {
			if !yield(f(k, v), v) {
				return
			}
		}
	}
}

func MapValues2[K, VIn, VOut any](seq iter.Seq2[K, VIn], f func(K, VIn) VOut) iter.Seq2[K, VOut] {
	return func(yield func(K, VOut) bool) {
		for k, v := range seq {
			if !yield(k, f(k, v)) {
				return
			}
		}
	}
}

func Concat[V any](seqs ...iter.Seq[V]) iter.Seq[V] {
	return func(yield func(V) bool) {
		for _, seq := range seqs {
			for e := range seq {
				if !yield(e) {
					return
				}
			}
		}
	}
}

func Concat2[K, V any](seqs ...iter.Seq2[K, V]) iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for _, seq := range seqs {
			for k, v := range seq {
				if !yield(k, v) {
					return
				}
			}
		}
	}
}

func Flatten[V any](seq iter.Seq[iter.Seq[V]]) iter.Seq[V] {
	return func(yield func(V) bool) {
		for s := range seq {
			for v := range s {
				if !yield(v) {
					return
				}
			}
		}
	}
}

func Flatten2[K, V any](seq iter.Seq[iter.Seq2[K, V]]) iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for s := range seq {
			for k, v := range s {
				if !yield(k, v) {
					return
				}
			}
		}
	}
}

func Any[V any](seq iter.Seq[V], f func(V) bool) bool {
	for v := range seq {
		if f(v) {
			return true
		}
	}
	return false
}

func Any2[K, V any](seq iter.Seq2[K, V], f func(K, V) bool) bool {
	for k, v := range seq {
		if f(k, v) {
			return true
		}
	}
	return false
}

func All[V any](seq iter.Seq[V], f func(V) bool) bool {
	for v := range seq {
		if !f(v) {
			return false
		}
	}
	return true
}

func All2[K, V any](seq iter.Seq2[K, V], f func(K, V) bool) bool {
	for k, v := range seq {
		if !f(k, v) {
			return false
		}
	}
	return true
}

func Equal[V comparable](x, y iter.Seq[V]) bool {
	for z := range Zip(x, y) {
		if z.Ok1 != z.Ok2 || z.V1 != z.V2 {
			return false
		}
	}
	return true
}

func Equal2[K, V comparable](x, y iter.Seq2[K, V]) bool {
	for z := range Zip2(x, y) {
		if z.Ok1 != z.Ok2 || z.K1 != z.K2 || z.V1 != z.V2 {
			return false
		}
	}
	return true
}

func EqualFunc[V1, V2 any](x iter.Seq[V1], y iter.Seq[V2], f func(V1, V2) bool) bool {
	for z := range Zip(x, y) {
		if z.Ok1 != z.Ok2 || !f(z.V1, z.V2) {
			return false
		}
	}
	return true
}

func EqualFunc2[K1, V1, K2, V2 any](x iter.Seq2[K1, V1], y iter.Seq2[K2, V2], f func(K1, V1, K2, V2) bool) bool {
	for z := range Zip2(x, y) {
		if z.Ok1 != z.Ok2 || !f(z.K1, z.V1, z.K2, z.V2) {
			return false
		}
	}
	return true
}

func Filter[V any](seq iter.Seq[V], f func(V) bool) iter.Seq[V] {
	return func(yield func(V) bool) {
		for v := range seq {
			if f(v) && !yield(v) {
				return
			}
		}
	}
}

func Filter2[K, V any](seq iter.Seq2[K, V], f func(K, V) bool) iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		for k, v := range seq {
			if f(k, v) && !yield(k, v) {
				return
			}
		}
	}
}

func Truncate[V any](seq iter.Seq[V], n int) iter.Seq[V] {
	return func(yield func(V) bool) {
		if n <= 0 {
			return
		}
		for v := range seq {
			if !yield(v) {
				return
			}
			if n--; n <= 0 {
				break
			}
		}
	}
}

func Truncate2[K, V any](seq iter.Seq2[K, V], n int) iter.Seq2[K, V] {
	return func(yield func(K, V) bool) {
		if n <= 0 {
			return
		}
		for k, v := range seq {
			if !yield(k, v) {
				return
			}
			if n--; n <= 0 {
				break
			}
		}
	}
}

func Reduce[Accum, V any](seq iter.Seq[V], accum Accum, f func(Accum, V) Accum) Accum {
	for v := range seq {
		accum = f(accum, v)
	}
	return accum
}

func ReduceOrError[Accum, V any](seq iter.Seq[V], accum Accum, f func(Accum, V) (Accum, error)) (Accum, error) {
	var err error
	for v := range seq {
		accum, err = f(accum, v)
		if err != nil {
			return accum, err
		}
	}
	return accum, nil
}

func Reduce2OrError[Accum, K, V any](seq iter.Seq2[K, V], accum Accum, f func(Accum, K, V) (Accum, error)) (Accum, error) {
	var err error
	for k, v := range seq {
		accum, err = f(accum, k, v)
		if err != nil {
			return accum, err
		}
	}
	return accum, nil
}

func Reduce2[Accum, K, V any](seq iter.Seq2[K, V], accum Accum, f func(Accum, K, V) Accum) Accum {
	for k, v := range seq {
		accum = f(accum, k, v)
	}
	return accum
}

func ZipTruncate[V1, V2 any](x iter.Seq[V1], y iter.Seq[V2]) iter.Seq2[V1, V2] {
	return func(yield func(z1 V1, z2 V2) bool) {
		next, stop := iter.Pull(y)
		defer stop()
		v2, ok := next()
		for v1 := range x {
			if !ok || !yield(v1, v2) {
				return
			}
			v2, ok = next()
		}
	}
}

type Zipped[V1, V2 any] struct {
	V1  V1
	Ok1 bool // whether V1 is present (if not, it will be false)
	V2  V2
	Ok2 bool // whether V2 is present (if not, it will be false)
}

func Zip[V1, V2 any](x iter.Seq[V1], y iter.Seq[V2]) iter.Seq[Zipped[V1, V2]] {
	return func(yield func(z Zipped[V1, V2]) bool) {
		next, stop := iter.Pull(y)
		defer stop()
		v2, ok2 := next()
		for v1 := range x {
			if !yield(Zipped[V1, V2]{v1, true, v2, ok2}) {
				return
			}
			v2, ok2 = next()
		}
		var zv1 V1
		for ok2 {
			if !yield(Zipped[V1, V2]{zv1, false, v2, ok2}) {
				return
			}
			v2, ok2 = next()
		}
	}
}

type Zipped2[K1, V1, K2, V2 any] struct {
	K1  K1
	V1  V1
	Ok1 bool // whether K1, V1 are present (if not, they will be false)
	K2  K2
	V2  V2
	Ok2 bool // whether K2, V2 are present (if not, they will be false)
}

func Zip2[K1, V1, K2, V2 any](x iter.Seq2[K1, V1], y iter.Seq2[K2, V2]) iter.Seq[Zipped2[K1, V1, K2, V2]] {
	return func(yield func(z Zipped2[K1, V1, K2, V2]) bool) {
		next, stop := iter.Pull2(y)
		defer stop()
		k2, v2, ok2 := next()
		for k1, v1 := range x {
			if !yield(Zipped2[K1, V1, K2, V2]{k1, v1, true, k2, v2, ok2}) {
				return
			}
			k2, v2, ok2 = next()
		}
		var zk1 K1
		var zv1 V1
		for ok2 {
			if !yield(Zipped2[K1, V1, K2, V2]{zk1, zv1, false, k2, v2, ok2}) {
				return
			}
			k2, v2, ok2 = next()
		}
	}
}
