package testutils

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	mult "github.com/copperexchange/krypton-primitives/pkg/threshold/mult/dkls23"
)

func MakeMult2Participants(t *testing.T, curve curves.Curve, baseOtReceiverOutput *ot.ReceiverRotOutput, baseOtSenderOutput *ot.SenderRotOutput, aliceTprng, bobTprng io.Reader, seededPrng csprng.CSPRNG, aliceSid, bobSid []byte) (alice *mult.Alice, bob *mult.Bob, err error) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, sha3.New256)
	require.NoError(t, err)
	authKeys, err := ttu.MakeTestAuthKeys(cipherSuite, 2)
	require.NoError(t, err)

	otProtocol, err := types.NewProtocol(curve, hashset.NewHashableHashSet(authKeys[0].(types.IdentityKey), authKeys[1].(types.IdentityKey)))
	require.NoError(t, err)

	alice, err = mult.NewAlice(authKeys[0], otProtocol, baseOtReceiverOutput, aliceSid, aliceTprng, seededPrng, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create alice")
	}
	bob, err = mult.NewBob(authKeys[1], otProtocol, baseOtSenderOutput, bobSid, bobTprng, seededPrng, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create bob")
	}
	return alice, bob, nil
}

func RunMult2(t *testing.T, alice *mult.Alice, bob *mult.Bob, aliceInput [mult.L]curves.Scalar) (b curves.Scalar, zA, zB *mult.OutputShares, err error) {
	t.Helper()
	b, r1out, err := bob.Round1()
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bob round 1 failed")
	}
	zA, r2out, err := alice.Round2(r1out, aliceInput)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "alice round 2 failed")
	}
	zB, err = bob.Round3(r2out)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "bob round 3 failed")
	}
	return b, zA, zB, nil
}
