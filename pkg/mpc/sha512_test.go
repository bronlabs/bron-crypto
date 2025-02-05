package mpc_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	randv2 "math/rand/v2"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/mpc"
)

func Test_Sha512(t *testing.T) {
	t.Parallel()

	prng := crand.Reader

	for range 16 {
		dealer := mpc.NewDealer()
		inputLen := 1 + randv2.IntN(32)
		input := make([]byte, inputLen)
		_, err := io.ReadFull(crand.Reader, input)
		require.NoError(t, err)

		expected := sha512.Sum512(input)
		shares := padAndShare(t, dealer, input, prng)

		circuit := mpc.NewCircuit(prng)
		var aliceOutput, bobOutput, charlieOutput [8]*mpc.BinaryShare

		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			gates := circuit.AliceGates()
			aliceOutput = mpc.Sha512(gates, shares[1])
			wg.Done()
		}()
		go func() {
			gates := circuit.BobGates()
			bobOutput = mpc.Sha512(gates, shares[2])
			wg.Done()
		}()
		go func() {
			gates := circuit.CharlieGates()
			charlieOutput = mpc.Sha512(gates, shares[3])
			wg.Done()
		}()
		wg.Wait()

		result := open(t, dealer, aliceOutput[:], bobOutput[:], charlieOutput[:])
		require.Equal(t, expected, result)
		fmt.Printf("rounds count: %d\n", circuit.RoundCount())
	}
}

func padAndShare(tb testing.TB, dealer *mpc.Dealer, input []byte, prng io.Reader) map[types.SharingID][]*mpc.BinaryShare {
	tb.Helper()

	var inputBlock [128]byte
	copy(inputBlock[:], input)
	inputBlock[len(input)] = 0x80
	copy(inputBlock[128-8:], binary.BigEndian.AppendUint64(nil, uint64(len(input)*8)))

	var inputUints [16]uint64
	for i := range inputUints {
		inputUints[i] = binary.BigEndian.Uint64(inputBlock[i*8 : (i+1)*8])
	}

	shares := make(map[types.SharingID][]*mpc.BinaryShare)
	shares[1] = make([]*mpc.BinaryShare, 16)
	shares[2] = make([]*mpc.BinaryShare, 16)
	shares[3] = make([]*mpc.BinaryShare, 16)

	for i := range inputUints {
		s := dealer.Share(inputUints[i], prng)
		shares[1][i] = s[1]
		shares[2][i] = s[2]
		shares[3][i] = s[3]
	}

	return shares
}

func open(tb testing.TB, dealer *mpc.Dealer, alice, bob, charlie []*mpc.BinaryShare) [64]byte {
	tb.Helper()

	var uintResult [8]uint64
	for i := range uintResult {
		var err error
		uintResult[i], err = dealer.Open(alice[i], bob[i], charlie[i])
		require.NoError(tb, err)
	}

	var byteResult [64]byte
	for i := range uintResult {
		binary.BigEndian.PutUint64(byteResult[8*i:8*(i+1)], uintResult[i])
	}

	return byteResult
}
