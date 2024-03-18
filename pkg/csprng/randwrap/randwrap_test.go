package randwrap

import (
	crand "crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/uints/uint128"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
)

func TestUniqueOutputs(t *testing.T) {
	t.Parallel()
	identities, err := testutils.MakeDeterministicTestAuthKeys(1)
	require.NoError(t, err)
	wrappingKey := identities[0]

	for _, n := range []int{5, 10, 256, 300} {
		for _, trialCount := range []int{10} {
			boundedN := n
			boundedTrialCount := trialCount
			t.Run(fmt.Sprintf("checkign uniqueness of %d samples of size [%d]byte", boundedTrialCount, boundedN), func(t *testing.T) {
				t.Parallel()

				wr, err := NewWrappedReader(crand.Reader, wrappingKey)
				require.NoError(t, err)

				seen := map[string]bool{}
				for trial := 0; trial < boundedTrialCount; trial++ {
					output := make([]byte, boundedN)
					readN, err := wr.Read(output)
					require.NoError(t, err)
					require.Equal(t, boundedN, readN)

					encodedOutput := hex.EncodeToString(output)
					_, exists := seen[encodedOutput]
					require.False(t, exists)
					seen[encodedOutput] = true
				}

			})
		}
	}
}

func TestIncrementNonce(t *testing.T) {
	t.Parallel()
	identities, err := testutils.MakeDeterministicTestAuthKeys(1)
	require.NoError(t, err)
	wrappingKey := identities[0]

	wr, err := NewWrappedReader(crand.Reader, wrappingKey)
	require.NoError(t, err)

	tag2Copy := wr.tag2.Clone()

	wrWithExpectedTag2 := &WrappedReader{
		deviceRandomnessDeterministicWrappingKey: wr.deviceRandomnessDeterministicWrappingKey,
		prk:                                      wr.prk,
		tag2:                                     tag2Copy,
	}

	p := 3
	q := 1
	output := make([]byte, p*NBytes+q)
	incrementCount := p + q

	_, err = wr.Read(output)
	require.NoError(t, err)

	for i := 0; i < incrementCount; i++ {
		wrWithExpectedTag2.tag2 = wrWithExpectedTag2.tag2.Add(uint128.One)
	}

	require.EqualValues(t, wrWithExpectedTag2.tag2, wr.tag2)

}
