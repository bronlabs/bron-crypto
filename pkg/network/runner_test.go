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

		r := network.NewSafeRunner[int](stubRunner[int]{
			run: func(*network.Router) (int, error) {
				return 7, nil
			},
		})

		got, err := r.Run(nil)
		require.NoError(t, err)
		require.Equal(t, 7, got)
	})

	t.Run("returns error on panic", func(t *testing.T) {
		t.Parallel()

		r := network.NewSafeRunner[int](stubRunner[int]{
			run: func(*network.Router) (int, error) {
				panic("boom")
			},
		})

		got, err := r.Run(nil)
		require.Error(t, err)
		require.Zero(t, got)
		require.Contains(t, err.Error(), "runner panicked")
		require.Contains(t, err.Error(), "boom")
	})
}
