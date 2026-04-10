package network_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/network"
)

type stubRunner[O any] struct {
	run func(*network.Router) (O, error)
}

func (r stubRunner[O]) Run(rt *network.Router) (O, error) {
	return r.run(rt)
}

func TestSafeRunnerRun(t *testing.T) {
	t.Parallel()

	t.Run("returns underlying result", func(t *testing.T) {
		t.Parallel()

		r, err := network.NewSafeRunner[int](stubRunner[int]{
			run: func(*network.Router) (int, error) {
				return 7, nil
			},
		})
		require.NoError(t, err)

		got, err := r.Run(nil)
		require.NoError(t, err)
		require.Equal(t, 7, got)
	})

	t.Run("returns error on panic", func(t *testing.T) {
		t.Parallel()

		r, err := network.NewSafeRunner[int](stubRunner[int]{
			run: func(*network.Router) (int, error) {
				panic("boom")
			},
		})
		require.NoError(t, err)

		got, err := r.Run(nil)
		require.Error(t, err)
		require.Zero(t, got)
		require.Contains(t, err.Error(), "runner panicked")
		require.Contains(t, err.Error(), "boom")
	})

	t.Run("rejects nil runner", func(t *testing.T) {
		t.Parallel()

		r, err := network.NewSafeRunner[int](nil)
		require.Nil(t, r)
		require.Error(t, err)
	})
}
