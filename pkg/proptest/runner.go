package proptest

import (
	"io"
	"testing"
)

type Context struct {
	iters int
	prng  io.Reader
}

func NewContext(iters int, prng io.Reader) *Context {
	return &Context{
		iters,
		prng,
	}
}

func RunPropertyCheck[V any](t *testing.T, ctx *Context, property Property[V]) {
	for range ctx.iters {
		if !property.Check(ctx.prng) {
			t.FailNow()
		}
	}
}
