package combinatorics

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

func CartesianProductGenerator[T, U any](t *[]T, u *[]U) <-chan *Product[T, U] {
	if t == nil {
		panic(errs.NewIsNil("t"))
	}
	if u == nil {
		panic(errs.NewIsNil("u"))
	}
	ch := make(chan *Product[T, U], 1)
	go func() {
		defer close(ch)
		if len(*t) == 0 || len(*u) == 0 {
			return
		}
		for _, xt := range *t {
			for _, xu := range *u {
				ch <- &Product[T, U]{
					First:  xt,
					Second: xu,
				}
			}
		}
	}()
	return ch
}

func CartesianProducts[T, U any](t []T, u []U) []*Product[T, U] {
	out := make([]*Product[T, U], len(t)*len(u))
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
