package iterutils

import "iter"

func Map[In, Out any](seq iter.Seq[In], f func(In) Out) iter.Seq[Out] {
	return func(yield func(Out) bool) {
		for in := range seq {
			if !yield(f(in)) {
				return
			}
		}
	}
}

func Map2Values[K, VIn, VOut any](seq iter.Seq2[K, VIn], f func(K, VIn) (K, VOut)) iter.Seq2[K, VOut] {
	return func(yield func(K, VOut) bool) {
		for k, v := range seq {
			if !yield(f(k, v)) {
				return
			}
		}
	}
}
