package mpc_test

import (
	crand "crypto/rand"
	"encoding/binary"
	"io"
	randv2 "math/rand/v2"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/mpc"
)

func Test_BinaryAndGate(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	circuit := mpc.NewCircuit(prng)

	for range 1024 * 1024 {
		secretA := randv2.Uint64()
		secretB := randv2.Uint64()

		dealer := mpc.NewDealer()
		sharesA := dealer.Share(secretA, prng)
		sharesB := dealer.Share(secretB, prng)

		expected := secretA & secretB
		actualShares := make([]*mpc.BinaryShare, 3)

		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			gates := circuit.AliceGates()
			actualShares[0] = gates.And(sharesA[1], sharesB[1])
			wg.Done()
		}()
		go func() {
			gates := circuit.BobGates()
			actualShares[1] = gates.And(sharesA[2], sharesB[2])
			wg.Done()
		}()
		go func() {
			gates := circuit.CharlieGates()
			actualShares[2] = gates.And(sharesA[3], sharesB[3])
			wg.Done()
		}()

		wg.Wait()
		actual, err := dealer.Open(actualShares...)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
}

func Test_BinaryOrGate(t *testing.T) {
	t.Parallel()

	prng := crand.Reader

	for range 1024 * 1024 {
		secretA := randv2.Uint64()
		secretB := randv2.Uint64()

		dealer := mpc.NewDealer()
		sharesA := dealer.Share(secretA, prng)
		sharesB := dealer.Share(secretB, prng)

		expected := secretA | secretB
		actualShares := make([]*mpc.BinaryShare, 3)
		circuit := mpc.NewCircuit(prng)

		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			gates := circuit.AliceGates()
			actualShares[0] = gates.Or(sharesA[1], sharesB[1])
			wg.Done()
		}()
		go func() {
			gates := circuit.BobGates()
			actualShares[1] = gates.Or(sharesA[2], sharesB[2])
			wg.Done()
		}()
		go func() {
			gates := circuit.CharlieGates()
			actualShares[2] = gates.Or(sharesA[3], sharesB[3])
			wg.Done()
		}()

		wg.Wait()
		actual, err := dealer.Open(actualShares...)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
}

func Test_BinaryAddGate(t *testing.T) {
	t.Parallel()

	prng := crand.Reader

	for range 1024 {
		secretA := randv2.Uint64()
		secretB := randv2.Uint64()

		dealer := mpc.NewDealer()
		sharesA := dealer.Share(secretA, prng)
		sharesB := dealer.Share(secretB, prng)

		expected := secretA + secretB
		actualShares := make([]*mpc.BinaryShare, 3)
		circuit := mpc.NewCircuit(prng)

		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			gates := circuit.AliceGates()
			actualShares[0] = gates.BinaryAdd(sharesA[1], sharesB[1])
			wg.Done()
		}()
		go func() {
			gates := circuit.BobGates()
			actualShares[1] = gates.BinaryAdd(sharesA[2], sharesB[2])
			wg.Done()
		}()
		go func() {
			gates := circuit.CharlieGates()
			actualShares[2] = gates.BinaryAdd(sharesA[3], sharesB[3])
			wg.Done()
		}()

		wg.Wait()
		actual, err := dealer.Open(actualShares...)
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	}
}

func randomUint64(tb testing.TB, prng io.Reader) uint64 {
	tb.Helper()

	var uint64Bytes [8]byte
	_, err := io.ReadFull(prng, uint64Bytes[:])
	require.NoError(tb, err)
	return binary.LittleEndian.Uint64(uint64Bytes[:])
}
