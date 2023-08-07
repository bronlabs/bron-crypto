package test_utils

import (
	"io"
	"testing"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/ot/base/vsot"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tecdsa/dkls23/mult"
)

func MakeMultParticipants(t *testing.T, cipherSuite *integration.CipherSuite, baseOtReceiverOutput *vsot.ReceiverOutput, baseOtSenderOutput *vsot.SenderOutput, alicePrng, bobPrng io.Reader, aliceSid, bobSid []byte) (alice *mult.Alice, bob *mult.Bob, err error) {
	t.Helper()

	alice, err = mult.NewAlice(cipherSuite.Curve, baseOtReceiverOutput, aliceSid, alicePrng, nil)
	if err != nil {
		return nil, nil, err
	}
	bob, err = mult.NewBob(cipherSuite.Curve, baseOtSenderOutput, bobSid, bobPrng, nil)
	if err != nil {
		return nil, nil, err
	}
	return alice, bob, nil
}

func RunMult(t *testing.T, alice *mult.Alice, bob *mult.Bob, aliceInput [mult.L]curves.Scalar) (zA, zB *mult.OutputShares, err error) {
	t.Helper()
	bobOutput, err := bob.Round1()
	if err != nil {
		return nil, nil, err
	}
	zA, aliceOutput, err := alice.Round2(bobOutput, aliceInput)
	if err != nil {
		return nil, nil, err
	}
	zB, err = bob.Round3(aliceOutput)
	if err != nil {
		return nil, nil, err
	}
	return zA, zB, nil
}
