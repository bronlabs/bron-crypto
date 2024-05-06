package pedersencomm_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm/pedersencomm"
	"github.com/stretchr/testify/require"
)

var (
	sessionId = []byte("00000001")
)

func TestSimpleHappyPath(t *testing.T) {
	sessionId := []byte("00000001")
	curves := []curves.Curve{k256.NewCurve()} //, p256.NewCurve(), pallas.NewCurve(), edwards25519.NewCurve(), bls12381.NewG1(), bls12381.NewG2()}
	for _, curve := range curves {
		c, err := pedersencomm.NewHomomorphicCommitter(sessionId, crand.Reader, curve)
		require.NoError(t, err)
		v, err := pedersencomm.NewHomomorphicVerifier(sessionId)
		require.NoError(t, err)
		message, err := curve.ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		commit, opening, err := c.Commit(message)
		require.NoError(t, err)
		err = v.Verify(commit, opening)
		require.NoError(t, err)
	}
}

type testCaseEntry struct {
	message    pedersencomm.Message
	opening    *pedersencomm.Opening
	commitment pedersencomm.Commitment
	err        error
}

func getEntries() []testCaseEntry {
	message_k256, _ := k256.NewCurve().ScalarField().Random(crand.Reader)
	message_p256, _ := p256.NewCurve().ScalarField().Random(crand.Reader)
	message_pallas, _ := pallas.NewCurve().ScalarField().Random(crand.Reader)
	message_ed25519, _ := edwards25519.NewCurve().ScalarField().Random(crand.Reader)
	message_bls12381g1, _ := bls12381.NewG1().ScalarField().Random(crand.Reader)
	message_bls12381g2, _ := bls12381.NewG2().ScalarField().Random(crand.Reader)
	var testResults = []testCaseEntry{
		{message: message_k256},
		{message: message_p256},
		{message: message_pallas},
		{message: message_ed25519},
		{message: message_bls12381g1},
		{message: message_bls12381g2},
	}
	for i := range testResults {
		c, _ := pedersencomm.NewHomomorphicCommitter(sessionId, crand.Reader, testResults[i].message.ScalarField().Curve())
		testCaseEntry := &testResults[i]
		testCaseEntry.commitment, testCaseEntry.opening, testCaseEntry.err = c.Commit(testCaseEntry.message)
	}
	return testResults
}

func TestDecommitShouldNotBeNil(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		require.NotNilf(t, testCaseEntry.opening.Witness, "decommit cannot be nil: Commit(%v)", testCaseEntry.message)
	}
}

func TestOpenOnValidCommitments(t *testing.T) {
	testResults := getEntries()
	v, err := pedersencomm.NewHomomorphicVerifier(sessionId)
	require.NoError(t, err)
	for _, testCaseEntry := range testResults {
		err := v.Verify(testCaseEntry.commitment, testCaseEntry.opening)
		require.NoErrorf(t, err, "commitment of message failed: %s", testCaseEntry.message)
	}
}

func TestOpenOnModifiedNonce(t *testing.T) {
	t.Parallel()
	v, err := pedersencomm.NewHomomorphicVerifier(sessionId)
	require.NoError(t, err)
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		localOpening := testCaseEntry.opening
		// Add a random scalar to the witness
		rnd, _ := testCaseEntry.commitment.Commitment.Curve().ScalarField().Random(crand.Reader)
		localOpening.Witness = localOpening.Witness.Add(rnd)
		// Verify and check for failure
		err := v.Verify(testCaseEntry.commitment, localOpening)
		require.Error(t, err)
		require.True(t, errs.IsVerification(err))
	}
}

func TestOpenOnModifiedCommitment(t *testing.T) {
	t.Parallel()
	v, err := pedersencomm.NewHomomorphicVerifier(sessionId)
	require.NoError(t, err)
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		localCommitment := testCaseEntry.commitment
		// Add a random point to the commitment
		rnd, _ := testCaseEntry.commitment.Commitment.Curve().Random(crand.Reader)
		localCommitment.Commitment = localCommitment.Commitment.Add(rnd)
		// Verify and check for failure
		err := v.Verify(localCommitment, testCaseEntry.opening)
		require.True(t, errs.IsVerification(err))
	}
}

// An empty decommit should fail to open
func TestOpenOnDefaultDecommitObject(t *testing.T) {
	t.Parallel()
	v, err := pedersencomm.NewHomomorphicVerifier(sessionId)
	require.NoError(t, err)
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		localOpening := testCaseEntry.opening
		localOpening.Witness = nil
		err := v.Verify(testCaseEntry.commitment, localOpening)
		require.True(t, errs.IsIsNil(err))
	}
}

func TestOpenOnNilCommitment(t *testing.T) {
	t.Parallel()
	v, err := pedersencomm.NewHomomorphicVerifier(sessionId)
	require.NoError(t, err)
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		err := v.Verify(pedersencomm.Commitment{nil}, testCaseEntry.opening)
		require.True(t, errs.IsIsNil(err))
	}
}

func TestHappyCombine(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		c, err := pedersencomm.NewHomomorphicCommitter(sessionId, crand.Reader, testCaseEntry.commitment.Commitment.Curve())
		require.NoError(t, err)
		v, err := pedersencomm.NewHomomorphicVerifier(sessionId)
		require.NoError(t, err)
		// Pick a random scalar to commit to
		messagePrime, err := testCaseEntry.commitment.Commitment.Curve().ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		comPrime, openingPrime, err := c.Commit(messagePrime)
		require.NoError(t, err)
		combinedCommitment, err := c.CombineCommitments(testCaseEntry.commitment, comPrime)
		require.NoError(t, err)
		combinedOpening, err := c.CombineOpenings(testCaseEntry.opening, openingPrime)
		require.NoError(t, err)
		err = v.Verify(combinedCommitment, combinedOpening)
		require.NoError(t, err)
	}
}

func TestOpenOnWrongCombine(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		c, err := pedersencomm.NewHomomorphicCommitter(sessionId, crand.Reader, testCaseEntry.commitment.Commitment.Curve())
		require.NoError(t, err)
		v, err := pedersencomm.NewHomomorphicVerifier(sessionId)
		require.NoError(t, err)
		// Pick a random scalar to commit to
		messagePrime, err := testCaseEntry.commitment.Commitment.Curve().ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		comPrime, _, err := c.Commit(messagePrime)
		require.NoError(t, err)
		// Pick another random scalar to get an unrelated opening
		messagePrime, err = testCaseEntry.commitment.Commitment.Curve().ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		_, openingPrime, err := c.Commit(messagePrime)
		require.NoError(t, err)
		combinedCommitment, err := c.CombineCommitments(testCaseEntry.commitment, comPrime)
		require.NoError(t, err)
		combinedOpening, err := c.CombineOpenings(testCaseEntry.opening, openingPrime)
		require.NoError(t, err)
		err = v.Verify(combinedCommitment, combinedOpening)
		require.Error(t, err)
		require.True(t, errs.IsVerification(err))
	}
}

func TestHappyScale(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		c, err := pedersencomm.NewHomomorphicCommitter(sessionId, crand.Reader, testCaseEntry.commitment.Commitment.Curve())
		require.NoError(t, err)
		v, err := pedersencomm.NewHomomorphicVerifier(sessionId)
		require.NoError(t, err)
		// Pick a random scalar for scaling
		rnd, err := testCaseEntry.commitment.Commitment.Curve().ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		scaledCommitment, err := c.ScaleCommitment(testCaseEntry.commitment, rnd.Nat())
		require.NoError(t, err)
		scaledOpening, err := v.ScaleOpening(testCaseEntry.opening, rnd.Nat())
		require.NoError(t, err)
		err = v.Verify(scaledCommitment, scaledOpening)
		require.NoError(t, err)
	}
}

func TestOpenOnWrongScale(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		c, err := pedersencomm.NewHomomorphicCommitter(sessionId, crand.Reader, testCaseEntry.commitment.Commitment.Curve())
		require.NoError(t, err)
		v, err := pedersencomm.NewHomomorphicVerifier(sessionId)
		require.NoError(t, err)
		// Pick a random scalar for commitment scaling
		rnd, err := testCaseEntry.commitment.Commitment.Curve().ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		scaledCommitment, err := c.ScaleCommitment(testCaseEntry.commitment, rnd.Nat())
		require.NoError(t, err)
		// Pick another random scalar for opening scaling
		rnd, err = testCaseEntry.commitment.Commitment.Curve().ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		scaledOpening, err := v.ScaleOpening(testCaseEntry.opening, rnd.Nat())
		require.NoError(t, err)
		err = v.Verify(scaledCommitment, scaledOpening)
		require.Error(t, err)
		require.True(t, errs.IsVerification(err))
	}
}
