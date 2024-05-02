package pedersencomm_test

import (
	crand "crypto/rand"
	"testing"

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
	sid = []byte("00000001")
)

func TestSimpleHappyPath(t *testing.T) {
	sessionId := []byte("00000001")
	c, err := pedersencomm.NewCommitterHomomorphic(crand.Reader, sessionId)
	require.NoError(t, err)
	v, err := pedersencomm.NewVerifierHomomorphic(sessionId)
	require.NoError(t, err)
	curve := k256.NewCurve()
	msg, err := curve.ScalarField().Random(crand.Reader)
	require.NoError(t, err)
	commit, opening, err := c.Commit(msg)
	require.NoError(t, err)
	err = v.Verify(commit, opening)
	require.NoError(t, err)
}

type testCaseEntry struct {
	msg pedersencomm.Message
	opn *pedersencomm.Opening
	com *pedersencomm.Commitment
	err error
}

func getEntries() []testCaseEntry {
	msg_k256, _ := k256.NewCurve().ScalarField().Random(crand.Reader)
	msg_p256, _ := p256.NewCurve().ScalarField().Random(crand.Reader)
	msg_pallas, _ := pallas.NewCurve().ScalarField().Random(crand.Reader)
	msg_ed25519, _ := edwards25519.NewCurve().ScalarField().Random(crand.Reader)
	msg_bls12381g1, _ := bls12381.NewG1().ScalarField().Random(crand.Reader)
	msg_bls12381g2, _ := bls12381.NewG2().ScalarField().Random(crand.Reader)
	var testResults = []testCaseEntry{
		{msg: msg_k256, opn: nil, com: nil, err: nil},
		{msg: msg_p256, opn: nil, com: nil, err: nil},
		{msg: msg_pallas, opn: nil, com: nil, err: nil},
		{msg: msg_ed25519, opn: nil, com: nil, err: nil},
		{msg: msg_bls12381g1, opn: nil, com: nil, err: nil},
		{msg: msg_bls12381g2, opn: nil, com: nil, err: nil},
	}
	for i := range testResults {
		c, _ := pedersencomm.NewCommitterHomomorphic(crand.Reader, sid)
		testCaseEntry := &testResults[i]
		testCaseEntry.com, testCaseEntry.opn, testCaseEntry.err = c.Commit(testCaseEntry.msg)
	}
	return testResults
}

func TestHappyPath(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		require.NoError(t, testCaseEntry.err)
	}
}

func TestDecommitShouldNotBeNil(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		require.NotNilf(t, testCaseEntry.opn.Witness, "decommit cannot be nil: Commit(%v)", testCaseEntry.msg)
	}
}

func TestOpenOnValidCommitments(t *testing.T) {
	testResults := getEntries()
	v, err := pedersencomm.NewVerifierHomomorphic(sid)
	require.NoError(t, err)
	for _, testCaseEntry := range testResults {
		// Verify each commitment
		err := v.Verify(testCaseEntry.com, testCaseEntry.opn)
		// There should be no error
		require.NoErrorf(t, err, "commitment of message failed: %s", testCaseEntry.msg)
	}
}

func TestOpenOnModifiedNonce(t *testing.T) {
	t.Parallel()
	v, err := pedersencomm.NewVerifierHomomorphic(sid)
	require.NoError(t, err)
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		localOpening := testCaseEntry.opn
		// Add a random scalar to the witness
		rnd, _ := testCaseEntry.com.Commitment.Curve().ScalarField().Random(crand.Reader)
		localOpening.Witness = localOpening.Witness.Add(rnd)
		// Verify and check for failure
		err := v.Verify(testCaseEntry.com, localOpening)
		require.Error(t, err)
		require.True(t, errs.IsVerification(err))
	}
}

func TestOpenOnModifiedCommitment(t *testing.T) {
	t.Parallel()
	v, err := pedersencomm.NewVerifierHomomorphic(sid)
	require.NoError(t, err)
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		localCommitment := testCaseEntry.com
		// Add a random point to the commitment
		rnd, _ := testCaseEntry.com.Commitment.Curve().Random(crand.Reader)
		localCommitment.Commitment = localCommitment.Commitment.Add(rnd)
		// Verify and check for failure
		err := v.Verify(localCommitment, testCaseEntry.opn)
		require.True(t, errs.IsVerification(err))
	}
}

// An empty decommit should fail to open
func TestOpenOnDefaultDecommitObject(t *testing.T) {
	t.Parallel()
	v, err := pedersencomm.NewVerifierHomomorphic(sid)
	require.NoError(t, err)
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		localOpening := testCaseEntry.opn
		localOpening.Witness = nil
		err := v.Verify(testCaseEntry.com, localOpening)
		require.True(t, errs.IsArgument(err))
	}
}

func TestOpenOnNilCommitment(t *testing.T) {
	t.Parallel()
	v, err := pedersencomm.NewVerifierHomomorphic(sid)
	require.NoError(t, err)
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		err := v.Verify(&pedersencomm.Commitment{nil}, testCaseEntry.opn)
		require.True(t, errs.IsArgument(err))
	}
}

func TestHappyCombine(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	c, err := pedersencomm.NewCommitterHomomorphic(crand.Reader, sid)
	require.NoError(t, err)
	v, err := pedersencomm.NewVerifierHomomorphic(sid)
	require.NoError(t, err)
	for _, testCaseEntry := range testResults {
		// Pick a random scalar to commit to
		msgPrime, err := testCaseEntry.com.Commitment.Curve().ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		comPrime, opnPrime, err := c.Commit(msgPrime)
		require.NoError(t, err)
		combinedCommitment, err := c.CombineCommitments(testCaseEntry.com, comPrime)
		require.NoError(t, err)
		combinedOpening, err := c.CombineOpenings(testCaseEntry.opn, opnPrime)
		require.NoError(t, err)
		err = v.Verify(combinedCommitment, combinedOpening)
		require.NoError(t, err)
	}
}

func TestOpenOnWrongCombine(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	c, err := pedersencomm.NewCommitterHomomorphic(crand.Reader, sid)
	require.NoError(t, err)
	v, err := pedersencomm.NewVerifierHomomorphic(sid)
	require.NoError(t, err)
	for _, testCaseEntry := range testResults {
		// Pick a random scalar to commit to
		msgPrime, err := testCaseEntry.com.Commitment.Curve().ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		comPrime, _, err := c.Commit(msgPrime)
		require.NoError(t, err)
		// Pick another random scalar to get an unrelated opening
		msgPrime, err = testCaseEntry.com.Commitment.Curve().ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		_, opnPrime, err := c.Commit(msgPrime)
		require.NoError(t, err)
		combinedCommitment, err := c.CombineCommitments(testCaseEntry.com, comPrime)
		require.NoError(t, err)
		combinedOpening, err := c.CombineOpenings(testCaseEntry.opn, opnPrime)
		require.NoError(t, err)
		err = v.Verify(combinedCommitment, combinedOpening)
		require.Error(t, err)
		require.True(t, errs.IsVerification(err))
	}
}

func TestHappyScale(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	c, err := pedersencomm.NewCommitterHomomorphic(crand.Reader, sid)
	require.NoError(t, err)
	v, err := pedersencomm.NewVerifierHomomorphic(sid)
	require.NoError(t, err)
	for _, testCaseEntry := range testResults {
		// Pick a random scalar for scaling
		rnd, err := testCaseEntry.com.Commitment.Curve().ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		scaledCommitment, err := c.ScaleCommitment(testCaseEntry.com, rnd.Nat())
		require.NoError(t, err)
		scaledOpening, err := v.ScaleOpening(testCaseEntry.opn, rnd.Nat())
		require.NoError(t, err)
		err = v.Verify(scaledCommitment, scaledOpening)
		require.NoError(t, err)
	}
}

func TestOpenOnWrongScale(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	c, err := pedersencomm.NewCommitterHomomorphic(crand.Reader, sid)
	require.NoError(t, err)
	v, err := pedersencomm.NewVerifierHomomorphic(sid)
	require.NoError(t, err)
	for _, testCaseEntry := range testResults {
		// Pick a random scalar for commitment scaling
		rnd, err := testCaseEntry.com.Commitment.Curve().ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		scaledCommitment, err := c.ScaleCommitment(testCaseEntry.com, rnd.Nat())
		require.NoError(t, err)
		// Pick another random scalar for opening scaling
		rnd, err = testCaseEntry.com.Commitment.Curve().ScalarField().Random(crand.Reader)
		require.NoError(t, err)
		scaledOpening, err := v.ScaleOpening(testCaseEntry.opn, rnd.Nat())
		require.NoError(t, err)
		err = v.Verify(scaledCommitment, scaledOpening)
		require.Error(t, err)
		require.True(t, errs.IsVerification(err))
	}
}
