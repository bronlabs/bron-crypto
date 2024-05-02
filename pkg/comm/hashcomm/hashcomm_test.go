package hashcomm_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/comm/hashcomm"
	"github.com/stretchr/testify/require"
)

var (
	h   = hashcomm.CommitmentHashFunction
	sid = []byte("00000001")
)

func TestSimpleHappyPath(t *testing.T) {
	sessionId := []byte("00000001")
	c, err := hashcomm.NewCommitter(crand.Reader, sessionId)
	require.NoError(t, err)
	v, err := hashcomm.NewVerifier(crand.Reader, sessionId)
	require.NoError(t, err)
	msg := []byte("test")
	commitment, opening, err := c.Commit(msg)
	require.NoError(t, err)
	require.NotNil(t, commitment.Commitment)
	require.NotNil(t, opening.Message())
	require.NotNil(t, opening.Witness)
	err = v.Verify(commitment, opening)
	require.NoError(t, err)
}

type testCaseEntry struct {
	msg hashcomm.Message
	opn *hashcomm.Opening
	com *hashcomm.Commitment
	err error
}

func getEntries() []testCaseEntry {
	var testResults = []testCaseEntry{
		{msg: []byte("This is a test message"), opn: nil, com: nil, err: nil},
		{msg: []byte("short msg"), opn: nil, com: nil, err: nil},
		{
			msg: []byte(`This input field is intentionally longer than the SHA256 block size and the largest
			rate of all SHA3 variants as defined in NIST FIPS PUB 202 (i.e. r = 1152 bits = 144 bytes for SHA3-224) 
			to cover cases where multiple blocks have to be processed.`),
			opn: nil, com: nil, err: nil,
		},
		{
			msg: []byte{0xFB, 0x1A, 0x18, 0x47, 0x39, 0x3C, 0x9F, 0x45, 0x5F, 0x29, 0x4C, 0x51, 0x42, 0x30, 0xA6, 0xB9},
			opn: nil, com: nil, err: nil,
		},
		// msg = \epsilon (empty string)
		{msg: []byte{}, opn: nil, com: nil, err: nil},
		// msg == nil
		{msg: nil, opn: nil, com: nil, err: nil},
	}
	for i := range testResults {
		c, _ := hashcomm.NewCommitter(crand.Reader, sid)
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

// Commitments should be 256b == 64B in length
func TestCommitmentsAreExpectedLength(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	expLen := h().Size()
	for _, testCaseEntry := range testResults {
		require.Lenf(t, testCaseEntry.com.Commitment, expLen, "commitment is not expected length: %v != %v", len(testCaseEntry.com.Commitment), expLen)
	}
}

func TestDecommitShouldNotBeNil(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		require.NotNilf(t, testCaseEntry.opn.Witness, "decommit cannot be nil: Commit(%v)", testCaseEntry.msg)
	}
}

func TestCommmitProducesDistinctCommitments(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool)
	testResults := getEntries()

	// Check the pre-computed commitments for uniquness
	for _, testCaseEntry := range testResults {
		// Slices cannot be used as hash keys, so we need to copy into
		// an array. Oh, go-lang.
		cee := make([]byte, h().Size())
		copy(cee[:], testCaseEntry.com.Commitment)

		serialised := hex.EncodeToString(cee)
		// Ensure each commit is unique
		require.NotContainsf(t, seen, serialised, "duplicate commit found: %v", cee)
		seen[serialised] = true
	}
}

// Commitments should be unique even for the same message since the nonce is
// randomly selected
func TestCommmitDistinctCommitments(t *testing.T) {
	t.Parallel()
	c, err := hashcomm.NewCommitter(crand.Reader, sid)
	require.NoError(t, err)
	seen := make(map[string]bool)
	msg := []byte("black lives matter")
	const iterations = 1000

	// Check the pre-computed commitments for uniquness
	for i := 0; i < iterations; i++ {
		// Compute a commitment
		com, _, err := c.Commit(msg)
		if err != nil {
			t.Error(err)
		}

		// Slices cannot be used as hash keys, so copy into an array
		cee := make([]byte, h().Size())
		copy(cee[:], []byte(com.Commitment))

		serialised := hex.EncodeToString(cee)

		// Ensure each commit is unique
		require.NotContainsf(t, seen, serialised, "duplicate commit found: %v", cee)
		seen[serialised] = true
	}
}

// Nonces must be 256b = 64B
func TestCommmitNonceIsExpectedLength(t *testing.T) {
	t.Parallel()
	expLen := h().Size()
	testResults := getEntries()

	// Check the pre-computed nonces
	for _, testCaseEntry := range testResults {
		require.Lenf(t, testCaseEntry.opn.Witness, expLen, "nonce has not expected length: %v != %v", len(testCaseEntry.opn.Witness), expLen)
	}
}

// Randomly selected nonces will be unique with overwhelming probability
func TestCommmitProducesDistinctNonces(t *testing.T) {
	t.Parallel()
	c, err := hashcomm.NewCommitter(crand.Reader, sid)
	require.NoError(t, err)
	seen := make(map[string]bool)
	msg := []byte("black lives matter")
	const iterations = 1000

	// Check the pre-computed commitments for uniquness
	for i := 0; i < iterations; i++ {
		// Compute a commitment
		_, opn, err := c.Commit(msg)
		require.NoError(t, err)

		// Ensure each nonce is unique
		serialised := hex.EncodeToString(opn.Witness)
		require.NotContainsf(t, seen, serialised, "duplicate nonce found: %v", opn.Witness)
		seen[serialised] = true
	}
}

func TestOpenOnValidCommitments(t *testing.T) {
	testResults := getEntries()
	v, err := hashcomm.NewVerifier(crand.Reader, sid)
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
	v, err := hashcomm.NewVerifier(crand.Reader, sid)
	require.NoError(t, err)
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		localOpening := testCaseEntry.opn
		// Modify the nonce MSB
		localOpening.Witness[0] ^= 0x80
		// Verify and check for failure
		err := v.Verify(testCaseEntry.com, localOpening)
		require.Error(t, err)
		require.True(t, errs.IsVerification(err))
	}
}

func TestOpenOnZeroPrefixNonce(t *testing.T) {
	t.Parallel()
	v, err := hashcomm.NewVerifier(crand.Reader, sid)
	require.NoError(t, err)
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		localOpening := testCaseEntry.opn
		// Modify the nonce
		localOpening.Witness[0] = 0x00
		localOpening.Witness[1] = 0x00
		localOpening.Witness[2] = 0x00
		localOpening.Witness[3] = 0x00
		localOpening.Witness[4] = 0x00
		localOpening.Witness[5] = 0x00
		localOpening.Witness[6] = 0x00
		localOpening.Witness[7] = 0x00
		localOpening.Witness[8] = 0x00
		localOpening.Witness[9] = 0x00
		localOpening.Witness[10] = 0x00
		// Verify and check for failure
		err := v.Verify(testCaseEntry.com, localOpening)
		require.True(t, errs.IsVerification(err))
	}
}

// An unrelated message should fail on open
// func TestOpenOnNewMessage(t *testing.T) {
// 	t.Parallel()
// 	v, err := hashcomm.NewVerifier(crand.Reader, sid)
// 	require.NoError(t, err)
// 	testResults := getEntries()
// 	for _, testCaseEntry := range testResults {
// 		localOpening := testCaseEntry.opn
// 		// Use a distinct message
// 		localOpening.Message = []byte("no one expects the spanish inquisition")
// 		// Verify and check for failure
// 		err := v.Verify(testCaseEntry.com, localOpening)
// 		require.True(t, errs.IsVerification(err))
// 	}
// }

// A modified message should fail on open
// func TestOpenOnModifiedMessage(t *testing.T) {
// 	t.Parallel()
// 	v, err := hashcomm.NewVerifier(crand.Reader, sid)
// 	require.NoError(t, err)
// 	testResults := getEntries()
// 	localTestResults := testResults
// 	for _, testCaseEntry := range localTestResults {
// 		// Skip the empty string message for this test case
// 		if len(testCaseEntry.msg) == 0 {
// 			continue
// 		}
// 		localOpening := testCaseEntry.opn
// 		// Modify the message LSB
// 		localOpening.message[0] ^= 0x01
// 		// Verify and check for failure
// 		err := v.Verify(testCaseEntry.com, localOpening)
// 		require.True(t, errs.IsVerification(err))
// 	}
// }

// A modified commitment should fail on open
func TestOpenOnModifiedCommitment(t *testing.T) {
	t.Parallel()
	v, err := hashcomm.NewVerifier(crand.Reader, sid)
	require.NoError(t, err)
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		// Copy and then modify the commitment
		localCommitment := testCaseEntry.com
		localCommitment.Commitment[6] ^= 0x33
		// Verify and check for failure
		err := v.Verify(localCommitment, testCaseEntry.opn)
		require.True(t, errs.IsVerification(err))
	}
}

// An empty decommit should fail to open
func TestOpenOnDefaultDecommitObject(t *testing.T) {
	t.Parallel()
	v, err := hashcomm.NewVerifier(crand.Reader, sid)
	require.NoError(t, err)
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		localOpening := testCaseEntry.opn
		localOpening.Witness = nil
		err := v.Verify(testCaseEntry.com, localOpening)
		require.True(t, errs.IsArgument(err))
	}
}

// A nil commit should return an error
func TestOpenOnNilCommitment(t *testing.T) {
	t.Parallel()
	v, err := hashcomm.NewVerifier(crand.Reader, sid)
	require.NoError(t, err)
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		err := v.Verify(&hashcomm.Commitment{[]byte{}}, testCaseEntry.opn)
		require.True(t, errs.IsArgument(err))
	}
}

// Too long commitment should produce an error
func TestOpenOnLongCommitment(t *testing.T) {
	t.Parallel()
	v, err := hashcomm.NewVerifier(crand.Reader, sid)
	require.NoError(t, err)
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		localCommitment := &hashcomm.Commitment{make([]byte, h().Size()+1)}
		copy(localCommitment.Commitment, testCaseEntry.com.Commitment)
		err := v.Verify(localCommitment, testCaseEntry.opn)
		require.True(t, errs.IsArgument(err))
	}
}

// Too short commitment should produce an error
func TestOpenOnShortCommitment(t *testing.T) {
	t.Parallel()
	v, err := hashcomm.NewVerifier(crand.Reader, sid)
	require.NoError(t, err)
	testResults := getEntries()
	for _, testCaseEntry := range testResults {
		localCommitment := &hashcomm.Commitment{make([]byte, h().Size()-1)}
		copy(localCommitment.Commitment, testCaseEntry.com.Commitment)
		err := v.Verify(localCommitment, testCaseEntry.opn)
		require.True(t, errs.IsArgument(err))
	}
}
