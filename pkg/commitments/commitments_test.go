package commitments_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/commitments"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

var h = sha256.New

func TestHappyPath(t *testing.T) {
	t.Parallel()
	message := []byte("something")
	h := sha3.New256
	commitment, witness, err := commitments.Commit(h, message)
	require.NoError(t, err)
	require.NotNil(t, commitment)
	require.NotNil(t, witness)

	openingError := commitments.Open(h, message, commitment, witness)
	require.NoError(t, openingError)
}

// An entry into our test table
type entry struct {
	// Input
	msg []byte

	// Result (actual, not expected)
	commit   commitments.Commitment
	decommit commitments.Witness
	err      error
}

// Test inputs and placeholders for results that will be filled in
// during init()
var testResults = []entry{
	{[]byte("This is a test message"), nil, nil, nil},
	{[]byte("short msg"), nil, nil, nil},
	{[]byte("This input field is intentionally longer than the SHA256 block size to ensure that the entire message is processed"),
		nil, nil, nil},
	{[]byte{0xFB, 0x1A, 0x18, 0x47, 0x39, 0x3C, 0x9F, 0x45, 0x5F, 0x29, 0x4C, 0x51, 0x42, 0x30, 0xA6, 0xB9},
		nil, nil, nil},
	// msg = \epsilon (empty string)
	{[]byte{}, nil, nil, nil},
	// msg == nil
	{nil, nil, nil, nil},
}

// Run our inputs through commit and record the outputs
func init() {
	for i := range testResults {
		entry := &testResults[i]
		entry.commit, entry.decommit, entry.err = commitments.Commit(h, entry.msg)
	}
}

// Computing commitments should never produce errors
func TestCommitWithoutErrors(t *testing.T) {
	t.Parallel()
	for _, entry := range testResults {
		require.NoError(t, entry.err)
	}
}

// Commitments should be 256b == 64B in length
func TestCommitmentsAreExpectedLength(t *testing.T) {
	t.Parallel()
	const expLen = 256 / 8
	for _, entry := range testResults {
		require.Lenf(t, entry.commit, expLen, "commitment is not expected length: %v != %v", len(entry.commit), expLen)
	}
}

// Decommit cannot be nil
func TestCommmitProducesDecommit(t *testing.T) {
	t.Parallel()
	for _, entry := range testResults {
		require.NotNilf(t, entry.decommit, "decommit cannot be nil: Commit(%v)", entry.msg)
	}
}

// Commitments should be unique
func TestCommmitProducesDistinctCommitments(t *testing.T) {
	t.Parallel()
	seen := make(map[string]bool)

	// Check the pre-computed commitments for uniquness
	for _, entry := range testResults {

		// Slices cannot be used as hash keys, so we need to copy into
		// an array. Oh, go-lang.
		cee := make([]byte, h().Size())
		copy(cee[:], entry.commit)

		serialized := hex.EncodeToString(cee)
		// Ensure each commit is unique
		require.NotContainsf(t, seen, serialized, "duplicate commit found: %v", cee)
		seen[serialized] = true
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
		c, _, err := commitments.Commit(h, msg)
		if err != nil {
			t.Error(err)
		}

		// Slices cannot be used as hash keys, so copy into an array
		cee := make([]byte, h().Size())
		copy(cee[:], []byte(c))

		serialzied := hex.EncodeToString(cee)

		// Ensure each commit is unique
		require.NotContainsf(t, seen, serialzied, "duplicate commit found: %v", cee)
		seen[serialzied] = true
	}
}

// Nonces must be 256b = 64B
func TestCommmitNonceIsExpectedLength(t *testing.T) {
	t.Parallel()
	const expLen = 256 / 8

	// Check the pre-computed nonces
	for _, entry := range testResults {
		require.Lenf(t, entry.decommit, expLen, "nonce is not expected length: %v != %v", len(entry.decommit), expLen)
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
		_, dee, err := commitments.Commit(h, msg)
		require.NoError(t, err)

		// Ensure each nonce is unique
		serialized := hex.EncodeToString(dee)
		require.NotContainsf(t, seen, serialized, "duplicate nonce found: %v", dee)
		seen[serialized] = true
	}
}

func TestOpenOnValidCommitments(t *testing.T) {
	for _, entry := range testResults {
		// Open each commitment
		err := commitments.Open(h, entry.msg, entry.commit, entry.decommit)
		// There should be no error
		require.NoErrorf(t, err, "commitment of message failed: %s", entry.msg)
	}
}

func TestOpenOnModifiedNonce(t *testing.T) {
	t.Parallel()
	for _, entry := range testResults {
		dʹ := entry.decommit[:]

		// Modify the nonce
		dʹ[0] ^= 0x40

		// Open and check for failure
		err := commitments.Open(h, entry.msg, entry.commit, dʹ)
		require.Error(t, err)
	}
}

func TestOpenOnZeroPrefixNonce(t *testing.T) {
	t.Parallel()
	for _, entry := range testResults {
		dʹ := entry.decommit[:]

		// Modify the nonce
		dʹ[0] = 0x00
		dʹ[1] = 0x00
		dʹ[2] = 0x00
		dʹ[3] = 0x00
		dʹ[4] = 0x00
		dʹ[5] = 0x00
		dʹ[6] = 0x00
		dʹ[7] = 0x00
		dʹ[8] = 0x00
		dʹ[9] = 0x00
		dʹ[10] = 0x00

		// Open and check for failure
		err := commitments.Open(h, entry.msg, entry.commit, dʹ)
		require.Error(t, err)
	}
}

// An unrelated message should fail on open
func TestOpenOnNewMessage(t *testing.T) {
	t.Parallel()
	for _, entry := range testResults {
		dʹ := entry.decommit[:]

		// Use a distinct message
		msg := []byte("no one expects the spanish inquisition")

		// Open and check for failure
		err := commitments.Open(h, msg, entry.commit, dʹ)
		require.Error(t, err)
	}
}

// A modified message should fail on open
func TestOpenOnModifiedMessage(t *testing.T) {
	t.Parallel()
	for _, entry := range testResults {
		// Skip the empty string message for this test case
		if len(entry.msg) == 0 {
			continue
		}

		// Modify the message _in situ_
		dʹ := entry.decommit[:]
		dʹ[1] ^= 0x99

		// Open and check for failure
		err := commitments.Open(h, entry.msg, entry.commit, dʹ)
		require.Error(t, err)
	}
}

// A modified commitment should fail on open
func TestOpenOnModifiedCommitment(t *testing.T) {
	t.Parallel()
	for _, entry := range testResults {
		// Copy and then modify the commitment
		cʹ := make([]byte, h().Size())
		copy(cʹ[:], entry.commit)
		cʹ[6] ^= 0x33

		// Open and check for failure
		err := commitments.Open(h, entry.msg, cʹ, entry.decommit)
		require.Error(t, err)
	}
}

// An empty decommit should fail to open
func TestOpenOnDefaultDecommitObject(t *testing.T) {
	t.Parallel()
	for _, entry := range testResults {
		// Open and check for failure
		err := commitments.Open(h, entry.msg, entry.commit, commitments.Witness{})
		require.Error(t, err)
	}
}

// A nil commit should return an error
func TestOpenOnNilCommitment(t *testing.T) {
	t.Parallel()
	err := commitments.Open(h, nil, nil, commitments.Witness{})
	require.Error(t, err)
}

// Ill-formed commitment should produce an error
func TestOpenOnLongCommitment(t *testing.T) {
	t.Parallel()
	for _, entry := range testResults {
		tooLong := make([]byte, h().Size()+1)
		copy(tooLong, entry.msg)
		// Open and check for failure
		err := commitments.Open(h, entry.msg, tooLong, entry.decommit)
		require.Error(t, err)
	}
}

// Ill-formed commitment should produce an error
func TestOpenOnShortCommitment(t *testing.T) {
	t.Parallel()
	for _, entry := range testResults {
		tooShort := make([]byte, h().Size()-1)
		copy(tooShort, entry.msg)
		// Open and check for failure
		err := commitments.Open(h, entry.msg, tooShort, entry.decommit)
		require.Error(t, err)
	}
}
