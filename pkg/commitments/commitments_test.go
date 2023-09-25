package commitments_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/commitments"
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
	commit  commitments.Commitment
	witness commitments.Witness
	err     error

	_ types.Incomparable
}

// Test inputs and placeholders for results that will be filled in
// during init()
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

// Run our inputs through commit and record the outputs
func init() {
	for i := range testResults {
		entry := &testResults[i]
		entry.commit, entry.witness, entry.err = commitments.Commit(h, entry.msg)
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
	expLen := h().Size()
	for _, entry := range testResults {
		require.Lenf(t, entry.commit, expLen, "commitment is not expected length: %v != %v", len(entry.commit), expLen)
	}
}

// Decommit cannot be nil
func TestCommmitProducesDecommit(t *testing.T) {
	t.Parallel()
	for _, entry := range testResults {
		require.NotNilf(t, entry.witness, "decommit cannot be nil: Commit(%v)", entry.msg)
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
		c, _, err := commitments.Commit(h, msg)
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
		_, dee, err := commitments.Commit(h, msg)
		require.NoError(t, err)

		// Ensure each nonce is unique
		serialised := hex.EncodeToString(dee)
		require.NotContainsf(t, seen, serialised, "duplicate nonce found: %v", dee)
		seen[serialised] = true
	}
}

func TestOpenOnValidCommitments(t *testing.T) {
	for _, entry := range testResults {
		// Open each commitment
		err := commitments.Open(h, entry.msg, entry.commit, entry.witness)
		// There should be no error
		require.NoErrorf(t, err, "commitment of message failed: %s", entry.msg)
	}
}

func TestOpenOnModifiedNonce(t *testing.T) {
	t.Parallel()
	for _, entry := range testResults {
		dʹ := entry.witness[:]

		// Modify the nonce
		dʹ[0] ^= 0x40

		// Open and check for failure
		err := commitments.Open(h, entry.msg, entry.commit, dʹ)
		require.True(t, errs.IsVerificationFailed(err))
	}
}

func TestOpenOnZeroPrefixNonce(t *testing.T) {
	t.Parallel()
	for _, entry := range testResults {
		dʹ := entry.witness[:]

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
		require.True(t, errs.IsVerificationFailed(err))
	}
}

// An unrelated message should fail on open
func TestOpenOnNewMessage(t *testing.T) {
	t.Parallel()
	for _, entry := range testResults {
		dʹ := entry.witness[:]

		// Use a distinct message
		msg := []byte("no one expects the spanish inquisition")

		// Open and check for failure
		err := commitments.Open(h, msg, entry.commit, dʹ)
		require.True(t, errs.IsVerificationFailed(err))
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
		dʹ := entry.witness[:]
		dʹ[1] ^= 0x99

		// Open and check for failure
		err := commitments.Open(h, entry.msg, entry.commit, dʹ)
		require.True(t, errs.IsVerificationFailed(err))
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
		err := commitments.Open(h, entry.msg, cʹ, entry.witness)
		require.True(t, errs.IsVerificationFailed(err))
	}
}

// An empty decommit should fail to open
func TestOpenOnDefaultDecommitObject(t *testing.T) {
	t.Parallel()
	for _, entry := range testResults {
		// Open and check for failure
		err := commitments.Open(h, entry.msg, entry.commit, commitments.Witness{})
		require.True(t, errs.IsInvalidArgument(err))
	}
}

// A nil commit should return an error
func TestOpenOnNilCommitment(t *testing.T) {
	t.Parallel()
	err := commitments.Open(h, nil, nil, commitments.Witness{})
	require.True(t, errs.IsInvalidArgument(err))
}

// Too long commitment should produce an error
func TestOpenOnLongCommitment(t *testing.T) {
	t.Parallel()
	for _, entry := range testResults {
		tooLong := make([]byte, h().Size()+1)
		copy(tooLong, entry.msg)
		// Open and check for failure
		err := commitments.Open(h, entry.msg, tooLong, entry.witness)
		require.True(t, errs.IsInvalidArgument(err))
	}
}

// Too short commitment should produce an error
func TestOpenOnShortCommitment(t *testing.T) {
	t.Parallel()
	for _, entry := range testResults {
		tooShort := make([]byte, h().Size()-1)
		copy(tooShort, entry.msg)
		// Open and check for failure
		err := commitments.Open(h, entry.msg, tooShort, entry.witness)
		require.True(t, errs.IsInvalidArgument(err))
	}
}
