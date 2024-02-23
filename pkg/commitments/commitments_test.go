package commitments_test

import (
	crand "crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
)

var h = commitments.CommitmentHashFunction

func TestHappyPath(t *testing.T) {
	t.Parallel()
	sessionId := []byte("sessionId")
	message := []byte("something")
	commitments.CommitmentHashFunction = sha3.New256
	commitment, witness, err := commitments.Commit(sessionId, crand.Reader, message)
	require.NoError(t, err)
	require.NotNil(t, commitment)
	require.NotNil(t, witness)

	openingError := commitments.Open(sessionId, commitment, witness, message)
	require.NoError(t, openingError)
}

// An entry into our test table
type entry struct {
	// Input
	msg []byte

	// Result (actual, not expected)
	commit  commitments.Commitment
	witness commitments.Witness
	err     error

	_ ds.Incomparable
}

func getEntries() []entry {
	var testResults = []entry{
		{msg: []byte("This is a test message"), commit: nil, witness: nil, err: nil},
		{msg: []byte("short msg"), commit: nil, witness: nil, err: nil},
		{
			msg:    []byte("This input field is intentionally longer than the SHA256 block size to ensure that the entire message is processed"),
			commit: nil, witness: nil, err: nil,
		},
		{
			msg:    []byte{0xFB, 0x1A, 0x18, 0x47, 0x39, 0x3C, 0x9F, 0x45, 0x5F, 0x29, 0x4C, 0x51, 0x42, 0x30, 0xA6, 0xB9},
			commit: nil, witness: nil, err: nil,
		},
		// msg = \epsilon (empty string)
		{msg: []byte{}, commit: nil, witness: nil, err: nil},
		// msg == nil
		{msg: nil, commit: nil, witness: nil, err: nil},
	}
	for i := range testResults {
		entry := &testResults[i]
		entry.commit, entry.witness, entry.err = commitments.CommitWithoutSession(crand.Reader, entry.msg)
	}
	return testResults
}

// Computing commitments should never produce errors
func TestCommitWithoutErrors(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, entry := range testResults {
		require.NoError(t, entry.err)
	}
}

// Commitments should be 256b == 64B in length
func TestCommitmentsAreExpectedLength(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	expLen := h().Size()
	for _, entry := range testResults {
		require.Lenf(t, entry.commit, expLen, "commitment is not expected length: %v != %v", len(entry.commit), expLen)
	}
}

// Decommit cannot be nil
func TestCommmitProducesDecommit(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, entry := range testResults {
		require.NotNilf(t, entry.witness, "decommit cannot be nil: Commit(%v)", entry.msg)
	}
}

// Commitments should be unique
func TestCommmitProducesDistinctCommitments(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool)
	testResults := getEntries()

	// Check the pre-computed commitments for uniquness
	for _, entry := range testResults {
		// Slices cannot be used as hash keys, so we need to copy into
		// an array. Oh, go-lang.
		cee := make([]byte, h().Size())
		copy(cee[:], entry.commit)

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
	seen := make(map[string]bool)
	msg := []byte("black lives matter")
	const iterations = 1000

	// Check the pre-computed commitments for uniquness
	for i := 0; i < iterations; i++ {
		// Compute a commitment
		c, _, err := commitments.CommitWithoutSession(crand.Reader, msg)
		if err != nil {
			t.Error(err)
		}

		// Slices cannot be used as hash keys, so copy into an array
		cee := make([]byte, h().Size())
		copy(cee[:], []byte(c))

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
	for _, entry := range testResults {
		require.Lenf(t, entry.witness, expLen, "nonce is not expected length: %v != %v", len(entry.witness), expLen)
	}
}

// Randomly selected nonces will be unique with overwhelming probability
func TestCommmitProducesDistinctNonces(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool)
	msg := []byte("black lives matter")
	const iterations = 1000

	// Check the pre-computed commitments for uniquness
	for i := 0; i < iterations; i++ {
		// Compute a commitment
		_, dee, err := commitments.CommitWithoutSession(crand.Reader, msg)
		require.NoError(t, err)

		// Ensure each nonce is unique
		serialised := hex.EncodeToString(dee)
		require.NotContainsf(t, seen, serialised, "duplicate nonce found: %v", dee)
		seen[serialised] = true
	}
}

func TestOpenOnValidCommitments(t *testing.T) {
	testResults := getEntries()
	for _, entry := range testResults {
		// OpenWithSession each commitment
		err := commitments.OpenWithoutSession(entry.commit, entry.witness, entry.msg)
		// There should be no error
		require.NoErrorf(t, err, "commitment of message failed: %s", entry.msg)
	}
}

func TestOpenOnModifiedNonce(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, entry := range testResults {
		dPrime := entry.witness[:]

		// Modify the nonce
		dPrime[0] ^= 0x40

		// OpenWithSession and check for failure
		err := commitments.OpenWithoutSession(entry.commit, dPrime, entry.msg)
		require.True(t, errs.IsVerification(err))
	}
}

func TestOpenOnZeroPrefixNonce(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, entry := range testResults {
		dPrime := entry.witness[:]

		// Modify the nonce
		dPrime[0] = 0x00
		dPrime[1] = 0x00
		dPrime[2] = 0x00
		dPrime[3] = 0x00
		dPrime[4] = 0x00
		dPrime[5] = 0x00
		dPrime[6] = 0x00
		dPrime[7] = 0x00
		dPrime[8] = 0x00
		dPrime[9] = 0x00
		dPrime[10] = 0x00

		// OpenWithSession and check for failure
		err := commitments.OpenWithoutSession(entry.commit, dPrime, entry.msg)
		require.True(t, errs.IsVerification(err))
	}
}

// An unrelated message should fail on open
func TestOpenOnNewMessage(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, entry := range testResults {
		dPrime := entry.witness[:]

		// Use a distinct message
		msg := []byte("no one expects the spanish inquisition")

		// OpenWithSession and check for failure
		err := commitments.OpenWithoutSession(entry.commit, dPrime, msg)
		require.True(t, errs.IsVerification(err))
	}
}

// A modified message should fail on open
func TestOpenOnModifiedMessage(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	localTestResults := testResults
	for _, entry := range localTestResults {
		// Skip the empty string message for this test case
		if len(entry.msg) == 0 {
			continue
		}

		// Modify the message _in situ_
		dPrime := entry.witness[:]
		dPrime[1] ^= 0x99

		// OpenWithSession and check for failure
		err := commitments.OpenWithoutSession(entry.commit, dPrime, entry.msg)
		require.True(t, errs.IsVerification(err))
	}
}

// A modified commitment should fail on open
func TestOpenOnModifiedCommitment(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, entry := range testResults {
		// Copy and then modify the commitment
		cPrime := make([]byte, h().Size())
		copy(cPrime[:], entry.commit)
		cPrime[6] ^= 0x33

		// OpenWithSession and check for failure
		err := commitments.OpenWithoutSession(cPrime, entry.witness, entry.msg)
		require.True(t, errs.IsVerification(err))
	}
}

// An empty decommit should fail to open
func TestOpenOnDefaultDecommitObject(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, entry := range testResults {
		// OpenWithSession and check for failure
		err := commitments.OpenWithoutSession(entry.commit, commitments.Witness{}, entry.msg)
		require.True(t, errs.IsArgument(err))
	}
}

// A nil commit should return an error
func TestOpenOnNilCommitment(t *testing.T) {
	t.Parallel()
	err := commitments.OpenWithoutSession(nil, commitments.Witness{}, nil)
	require.True(t, errs.IsArgument(err))
}

// Too long commitment should produce an error
func TestOpenOnLongCommitment(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, entry := range testResults {
		tooLong := make([]byte, h().Size()+1)
		copy(tooLong, entry.msg)
		// OpenWithSession and check for failure
		err := commitments.OpenWithoutSession(tooLong, entry.witness, entry.msg)
		require.True(t, errs.IsArgument(err))
	}
}

// Too short commitment should produce an error
func TestOpenOnShortCommitment(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, entry := range testResults {
		tooShort := make([]byte, h().Size()-1)
		copy(tooShort, entry.msg)
		// OpenWithSession and check for failure
		err := commitments.OpenWithoutSession(tooShort, entry.witness, entry.msg)
		require.True(t, errs.IsArgument(err))
	}
}
