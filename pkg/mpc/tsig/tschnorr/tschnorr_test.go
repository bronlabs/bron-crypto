package tschnorr_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/dkg/gennaro"
	session_testutils "github.com/bronlabs/bron-crypto/pkg/mpc/session/testutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr"
	ltu "github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tschnorr/lindell22/testutils"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

func TestPublicMaterialUnmarshalCBORRejectsInvalidPublicKey(t *testing.T) {
	t.Parallel()

	group := k256.NewCurve()
	prng := pcg.NewRandomised()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	ac, err := threshold.NewThresholdAccessStructure(2, shareholders)
	require.NoError(t, err)
	ctxs := session_testutils.MakeRandomContexts(t, shareholders, prng)

	parties := make(map[sharing.ID]*gennaro.Participant[*k256.Point, *k256.Scalar], 3)
	for id := range shareholders.Iter() {
		participant, err := gennaro.NewParticipant(ctxs[id], group, ac, fiatshamir.Name, prng)
		require.NoError(t, err)
		parties[id] = participant
	}

	shard := ltu.DoLindell22DKG(t, parties)[1]
	publicMaterial := shard.PublicKeyMaterial()
	publicMaterial.VerificationVector().Coefficients()[0] = group.OpIdentity()

	data, err := publicMaterial.MarshalCBOR()
	require.NoError(t, err)

	var decoded tschnorr.PublicMaterial[*k256.Point, *k256.Scalar]
	err = decoded.UnmarshalCBOR(data)
	require.Error(t, err)
}
