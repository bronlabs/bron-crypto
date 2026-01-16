package errs2_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
)

func TestSanity(t *testing.T) {
	t.Parallel()

	e1 := errs2.New("an error occurred")
	require.Error(t, e1)
	require.Equal(t, "an error occurred", e1.Error())

	e2 := e1.WithMessage("additional context is %d", 42)
	require.Error(t, e2)
	require.Equal(t, "ERROR: an error occurred: additional context is 42\n", fmt.Sprintf("%s", e2))

	tag := "code"
	e3 := e2.WithTag(tag, "E123")
	require.Error(t, e3)
	require.Equal(t, "ERROR: an error occurred: additional context is 42\n--- Tags: {\"code\":\"E123\"}\n", fmt.Sprintf("%s", e3))

	tags := e3.Tags()
	require.Contains(t, tags, tag)
	value, found := e3.Tags()[tag]
	require.True(t, found)
	require.Equal(t, "E123", value)

	v3, exists3 := errs2.HasTag(e3, tag)
	require.True(t, exists3)
	require.Equal(t, "E123", v3)

	require.True(t, errs2.Is(e3, e1))
	require.True(t, errs2.Is(e3, e2))

	e4 := e3.WithStackFrame()
	v4, exists4 := errs2.HasTag(e4, tag)
	require.True(t, exists4)
	require.Equal(t, "E123", v4)

	e5 := errs2.New("a different error")

	e6 := errs2.Join(e4, e5)

	require.True(t, errs2.Is(e6, e1))
	require.True(t, errs2.Is(e6, e2))
	require.True(t, errs2.Is(e6, e3))
	require.True(t, errs2.Is(e6, e4))
	require.True(t, errs2.Is(e6, e5))
	require.True(t, errs2.Is(e6, e6))

	// require.Fail(t, "%+v", e)
	// require.Fail(t, "%+v", e2)
	// require.Fail(t, "%+v", e3)
	// require.Fail(t, "%+v", e4)
}

var errFoo = errs2.New("FOO")

func foo() error {
	return errFoo.WithMessage("foo error")
}

func bar() error {
	return errs2.Wrap(foo()).WithMessage("bar error")
}

func TestUnwrap(t *testing.T) {
	err := bar()
	require.ErrorIs(t, err, errFoo)

	wrappedErr := errs2.Unwrap(err)
	require.Len(t, wrappedErr, 1)
	require.ErrorIs(t, wrappedErr[0], errFoo)
}
