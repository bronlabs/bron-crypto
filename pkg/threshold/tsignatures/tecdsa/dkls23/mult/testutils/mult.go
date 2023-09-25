package testutils

import (
	"io"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/dkls23/mult"
)

func MakeMultParticipants(t *testing.T, cipherSuite *integration.CipherSuite, baseOtReceiverOutput *vsot.ReceiverOutput, baseOtSenderOutput *vsot.SenderOutput, aliceTprng, bobTprng io.Reader, seededPrng csprng.CSPRNG, aliceSid, bobSid []byte) (alice *mult.Alice, bob *mult.Bob, err error) {
	t.Helper()

	alice, err = mult.NewAlice(cipherSuite.Curve, baseOtReceiverOutput, aliceSid, aliceTprng, seededPrng, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create alice")
	}
	bob, err = mult.NewBob(cipherSuite.Curve, baseOtSenderOutput, bobSid, bobTprng, seededPrng, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not create bob")
	}
	return alice, bob, nil
}

func RunMult(t *testing.T, alice *mult.Alice, bob *mult.Bob, aliceInput [mult.L]curves.Scalar) (zA, zB *mult.OutputShares, err error) {
	t.Helper()
	bobOutput, err := bob.Round1()
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "bob round 1 failed")
	}
	zA, aliceOutput, err := alice.Round2(bobOutput, aliceInput)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "alice round 2 failed")
	}
	zB, err = bob.Round3(aliceOutput)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "bob round 3 failed")
	}
	return zA, zB, nil
}
