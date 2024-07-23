package trusted_dealer_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/combinatorics"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/rsa"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/intshamir"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/trsa/damgard/keygen/trusted_dealer"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_Sanity(t *testing.T) {
	t.Parallel()

	const th = 2
	const n = 3
	prng := crand.Reader
	identities, err := testutils.MakeDeterministicTestIdentities(n)
	require.NoError(t, err)
	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, th) // dummy curve
	require.NoError(t, err)

	rsaKey, err := rsa.GenKeys(prng, 1024)
	require.NoError(t, err)

	shards, err := trusted_dealer.Deal(protocol, rsaKey, prng)
	require.NoError(t, err)
	require.NotNil(t, shards)

	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	idToSharingId := sharingCfg.Reverse()

	combinations, err := combinatorics.Combinations(identities, th)
	require.NoError(t, err)
	for j, c := range combinations {
		t.Run(fmt.Sprintf("combination %d matches d", j), func(t *testing.T) {
			t.Parallel()

			shares := make([]*intshamir.Share, th)
			for i, id := range c {
				sharingId, ok := idToSharingId.Get(id)
				require.True(t, ok)
				shard, ok := shards.Get(id)
				require.True(t, ok)

				shares[i] = &intshamir.Share{
					Id:    sharingId,
					Value: shard.Di,
				}
			}
			intDealer := intshamir.NewDealer(th, n)
			dRecovered := intDealer.Combine(shares)

			require.True(t, dRecovered.Eq(rsaKey.D) == 1)
		})
	}
}
