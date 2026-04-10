package tbls_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tbls"
	tu "github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tbls/boldyreva02/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
)

func TestPublicMaterialUnmarshalCBORRejectsInvalidPublicKey(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	group := bls12381.NewG1()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)
	parties := make(map[sharing.ID]*gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar], 3)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties[id] = p
	}

	shard := tu.DoBoldyrevaDKG(t, parties, true)[1]
	publicMaterial := shard.PublicKeyMaterial()
	publicMaterial.VerificationVector().Coefficients()[0] = group.OpIdentity()

	data, err := publicMaterial.MarshalCBOR()
	require.NoError(t, err)

	var decoded tbls.PublicMaterial[*bls12381.PointG1, *bls12381.BaseFieldElementG1, *bls12381.PointG2, *bls12381.BaseFieldElementG2, *bls12381.GtElement, *bls12381.Scalar]
	err = decoded.UnmarshalCBOR(data)
	require.Error(t, err)
}

func TestNewShortKeyShardRejectsMismatchedPublicKey(t *testing.T) {
	t.Parallel()

	prng := pcg.NewRandomised()
	group := bls12381.NewG1()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)

	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)
	parties := make(map[sharing.ID]*gennaro.Participant[*bls12381.PointG1, *bls12381.Scalar], 3)
	for id := range shareholders.Iter() {
		p, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties[id] = p
	}

	shards := tu.DoBoldyrevaDKG(t, parties, true)
	shard := shards[1]

	wrongPublicKey, err := bls.NewPublicKey(group.Generator().Double())
	require.NoError(t, err)

	rebuilt, err := tbls.NewShortKeyShard(shard.Share(), wrongPublicKey, shard.VerificationVector(), shard.AccessStructure())
	require.Error(t, err)
	require.Nil(t, rebuilt)
}
