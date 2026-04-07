package ioutils_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/utils/ioutils"
)

func TestWriteConcatWritesAllData(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	n, err := ioutils.WriteConcat(&buf, []byte("ab"), []byte("cd"))
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, []byte("abcd"), buf.Bytes())
}
