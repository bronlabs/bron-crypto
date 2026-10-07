package prng_test

import (
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/prng"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

// TestNewThreadSafeReader_Concurrent exercises concurrent reads on a wrapped
// single-threaded PRNG; run with -race this fails if the wrapper does not
// serialise access.
func TestNewThreadSafeReader_Concurrent(t *testing.T) {
	t.Parallel()

	r := prng.NewThreadSafeReader(pcg.NewRandomised())
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 64)
			for range 1000 {
				n, err := io.ReadFull(r, buf)
				if err != nil || n != len(buf) {
					t.Errorf("read failed: n=%d err=%v", n, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestNewThreadSafeReader_PassThrough checks the wrapper preserves the
// wrapped reader's byte stream.
func TestNewThreadSafeReader_PassThrough(t *testing.T) {
	t.Parallel()

	a := pcg.New(7, 13)
	b := prng.NewThreadSafeReader(pcg.New(7, 13))
	want := make([]byte, 256)
	got := make([]byte, 256)
	_, err := io.ReadFull(a, want)
	require.NoError(t, err)
	_, err = io.ReadFull(b, got)
	require.NoError(t, err)
	require.Equal(t, want, got)
}
