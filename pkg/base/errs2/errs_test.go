package errs2_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/stretchr/testify/require"
)

func TestSanity(t *testing.T) {
	t.Parallel()

	e1 := errs2.New("an error occurred")
	require.Error(t, e1)
	require.Equal(t, "an error occurred", e1.Error())

	e2 := errs2.WrapWithMessage(e1, "additional context is %d", 42)
	require.Error(t, e2)
	require.Equal(t, "an error occurred (additional context is 42)", e2.Error())

	tag := errs2.Tag("code")
	e3 := errs2.AttachTag(e2, tag, "E123")
	require.Error(t, e3)
	require.Equal(t, "an error occurred (additional context is 42)", e3.Error())

	taggedErr, ok := e3.(errs2.TaggedError)
	require.True(t, ok)
	tags := taggedErr.Tags()
	require.Contains(t, tags, tag)
	value, found := taggedErr.TagValue(tag)
	require.True(t, found)
	require.Equal(t, "E123", value)

	v3, exists3 := errs2.HasTag(e3, tag)
	require.True(t, exists3)
	require.Equal(t, "E123", v3)

	require.True(t, errs2.Is(e3, e1))
	require.True(t, errs2.Is(e3, e2))

	e4 := errs2.Wrap(e3)
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
	require.Fail(t, "%+v", e4)
}
