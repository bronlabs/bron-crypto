package proptest

import (
	"fmt"
	"testing"
)

type Context struct {
	iters int
}

func NewContext(iters int) *Context {
	return &Context{
		iters,
	}
}

func Run[V any](t *testing.T, ctx *Context, properties ...Property[V]) {
	t.Parallel()
	for iter := range ctx.iters {
		t.Run(fmt.Sprintf("iter-%d", iter), func(t *testing.T) {
			for i, prop := range properties {
				t.Run(fmt.Sprintf("property-%d", i), func(t *testing.T) {
					prop.Check()
				})
			}
		})
	}
}
