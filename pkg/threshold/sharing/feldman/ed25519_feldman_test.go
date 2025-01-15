package feldman_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/proofs/dlog/batch_schnorr"
	randomisedFischlin "github.com/bronlabs/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/shamir"
)

var testCurve = edwards25519.NewCurve()

func TestEd25519FeldmanSplitInvalidArgs(t *testing.T) {
	t.Parallel()
	_, err := feldman.NewDealer(0, 0, testCurve)
	require.Error(t, err)
	_, err = feldman.NewDealer(3, 2, testCurve)
	require.Error(t, err)
	_, err = feldman.NewDealer(1, 10, testCurve)
	require.Error(t, err)
	scheme, err := feldman.NewDealer(2, 3, testCurve)
	require.NoError(t, err)
	require.NotNil(t, scheme)
}

func TestEd25519FeldmanCombineNoShares(t *testing.T) {
	t.Parallel()
	scheme, err := feldman.NewDealer(2, 3, testCurve)
	require.NoError(t, err)
	require.NotNil(t, scheme)
	_, err = scheme.Combine()
	require.Error(t, err)
}

func TestEd25519FeldmanCombineDuplicateShare(t *testing.T) {
	t.Parallel()
	scheme, err := feldman.NewDealer(2, 3, testCurve)
	require.NoError(t, err)
	require.NotNil(t, scheme)
	_, err = scheme.Combine([]*shamir.Share{
		{
			Id:    1,
			Value: testCurve.ScalarField().New(3),
		},
		{
			Id:    1,
			Value: testCurve.ScalarField().New(3),
		},
	}...)
	require.Error(t, err)
}

func TestEd25519FeldmanCombineBadIdentifier(t *testing.T) {
	t.Parallel()
	scheme, err := feldman.NewDealer(2, 3, testCurve)
	require.NoError(t, err)
	require.NotNil(t, scheme)
	shares := []*shamir.Share{
		{
			Id:    0,
			Value: testCurve.ScalarField().New(3),
		},
		{
			Id:    2,
			Value: testCurve.ScalarField().New(3),
		},
	}
	_, err = scheme.Combine(shares...)
	require.Error(t, err)
	shares[0] = &shamir.Share{
		Id:    4,
		Value: testCurve.ScalarField().New(3),
	}
	_, err = scheme.Combine(shares...)
	require.Error(t, err)
}

func TestEd25519FeldmanCombineSingle(t *testing.T) {
	t.Parallel()
	scheme, err := feldman.NewDealer(2, 3, testCurve)
	require.NoError(t, err)
	require.NotNil(t, scheme)

	secret, err := testCurve.ScalarField().Hash([]byte("test"))
	require.NoError(t, err)
	batchSchnorr, err := batch_schnorr.NewSigmaProtocol(testCurve.Generator(), crand.Reader)
	require.NoError(t, err)
	fischlinBatchSchnorr, err := randomisedFischlin.NewCompiler(batchSchnorr, crand.Reader)
	require.NoError(t, err)
	prover, err := fischlinBatchSchnorr.NewProver([]byte("test"), nil)
	require.NoError(t, err)
	commitments, shares, proof, err := scheme.Split(secret, prover, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, shares)
	for _, s := range shares {
		verifier, err := fischlinBatchSchnorr.NewVerifier([]byte("test"), nil)
		require.NoError(t, err)
		err = feldman.Verify(s, commitments, verifier, proof)
		require.NoError(t, err)
	}
	secret2, err := scheme.Combine(shares...)
	require.NoError(t, err)
	require.Equal(t, secret2, secret)
}

func TestEd25519FeldmanAllCombinations(t *testing.T) {
	t.Parallel()
	scheme, err := feldman.NewDealer(3, 5, testCurve)
	require.NoError(t, err)
	require.NotNil(t, scheme)

	secret, err := testCurve.ScalarField().Hash([]byte("test"))
	require.NoError(t, err)

	dlogProofProtocol, err := batch_schnorr.NewSigmaProtocol(testCurve.Generator(), crand.Reader)
	require.NoError(t, err)
	randomisedFischlinCompiler, err := randomisedFischlin.NewCompiler(dlogProofProtocol, crand.Reader)
	require.NoError(t, err)

	sid := []byte("TestEd25519FeldmanAllCombinations")

	prover, err := randomisedFischlinCompiler.NewProver(sid, nil)
	require.NoError(t, err)
	commitments, shares, proof, err := scheme.Split(secret, prover, crand.Reader)
	for _, s := range shares {
		verifier, err := randomisedFischlinCompiler.NewVerifier(sid, nil)
		require.NoError(t, err)
		err = feldman.Verify(s, commitments, verifier, proof)
		require.NoError(t, err)
	}
	require.NoError(t, err)
	require.NotNil(t, shares)
	// There are 5*4*3 possible combinations
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			if i == j {
				continue
			}
			for k := 0; k < 5; k++ {
				if i == k || j == k {
					continue
				}

				rSecret, err := scheme.Combine(shares[i], shares[j], shares[k])
				require.NoError(t, err)
				require.NotNil(t, rSecret)
				require.Equal(t, rSecret, secret)
			}
		}
	}
}
