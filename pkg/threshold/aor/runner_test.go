package aor_test

import (
	crand "crypto/rand"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	ntu "github.com/bronlabs/bron-crypto/pkg/network/testutils"
	tu "github.com/bronlabs/bron-crypto/pkg/threshold/aor/testutils"
	ttu "github.com/bronlabs/bron-crypto/pkg/transcripts/testutils"
)

func TestHappyPathRunner(t *testing.T) {
	t.Parallel()

	const iters = 128
	testAccessStructures := []int{
		2,
		3,
		5,
		11,
	}
	for _, total := range testAccessStructures {
		t.Run(fmt.Sprintf("total=%d", total), func(t *testing.T) {
			t.Parallel()
			testHappyPathRunner(t, iters, total)
		})
	}
}

func testHappyPathRunner(t *testing.T, iters, total int) {
	t.Helper()

	const sampleLength = 32
	for i := range iters {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			t.Parallel()

			prng := crand.Reader
			quorum := ntu.MakeRandomQuorum(t, prng, total)
			tapes := ttu.MakeRandomTapes(t, prng, quorum)
			runners := tu.MakeAgreeOnRandomRunners(t, quorum, tapes, sampleLength)
			samples := ntu.TestExecuteRunners(t, runners)

			t.Run("should generate valid samples", func(t *testing.T) {
				t.Parallel()
				require.Len(t, samples, total)
				s, ok := samples[quorum.List()[0]]
				require.True(t, ok)

				for id := range quorum.Iter() {
					si, ok := samples[id]
					require.True(t, ok)
					require.Equal(t, s, si)
					require.Len(t, si, sampleLength)
				}
			})

			t.Run("should match transcripts", func(t *testing.T) {
				t.Parallel()
				tapeValues := make([][]byte, quorum.Size())
				for i, tape := range slices.Collect(maps.Values(tapes)) {
					var err error
					tapeValues[i], err = tape.ExtractBytes("test", 32)
					require.NoError(t, err)
					if i > 0 {
						require.True(t, slices.Equal(tapeValues[i-1], tapeValues[i]))
					}
				}
			})
		})
	}
}
