package combinatorics

import (
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

type CartesianProduct[T, U any] struct {
	T T
	U U
}

type CartesianPower[T any] []T

type MultiCartesianProduct CartesianPower[any]

func CartesianProductGenerator[T, U any](t *[]T, u *[]U) <-chan *CartesianProduct[T, U] {
	if t == nil {
		panic(errs.NewIsNil("t"))
	}
	if u == nil {
		panic(errs.NewIsNil("u"))
	}
	ch := make(chan *CartesianProduct[T, U], 1)
	go func() {
		defer close(ch)
		if len(*t) == 0 || len(*u) == 0 {
			return
		}
		for _, xt := range *t {
			for _, xu := range *u {
				ch <- &CartesianProduct[T, U]{
					T: xt,
					U: xu,
				}
			}
		}
	}()
	return ch
}

func CartesianProducts[T, U any](t []T, u []U) []*CartesianProduct[T, U] {
	out := make([]*CartesianProduct[T, U], len(t)*len(u))
	if len(t) == 0 || len(u) == 0 {
		return out
	}
	i := 0
	for p := range CartesianProductGenerator(&t, &u) {
		out[i] = p
		i++
	}
	return out
}
