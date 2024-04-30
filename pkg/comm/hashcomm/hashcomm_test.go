package hashcomm

import (
	crand "crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/stretchr/testify/require"
)

var (
	h   = CommitmentHashFunction
	sid = []byte("00000001")
)

func TestHappyPath(t *testing.T) {
	sessionId := []byte("00000001")
	c := NewCommitter(sessionId)
	v := NewVerifier(sessionId)
	msg := []byte("test")
	commitment, opening, err := c.Commit(crand.Reader, msg)
	require.NoError(t, err)
	require.NotNil(t, commitment.commitment)
	require.NotNil(t, opening.message)
	require.NotNil(t, opening.witness)
	err = v.Verify(commitment, opening)
	require.NoError(t, err)
}

// An entry into our test table
type entry struct {
	// Input
	msg Message
	// Output
	opn *Opening
	com *Commitment
	err error
}

func getEntries() []entry {
	var testResults = []entry{
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
		c := NewCommitter(sid)
		entry := &testResults[i]
		entry.com, entry.opn, entry.err = c.Commit(crand.Reader, entry.msg)
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
		require.Lenf(t, entry.com.commitment, expLen, "commitment is not expected length: %v != %v", len(entry.com.commitment), expLen)
	}
}

// Decommit cannot be nil
func TestCommmitProducesDecommit(t *testing.T) {
	t.Parallel()
	testResults := getEntries()
	for _, entry := range testResults {
		require.NotNilf(t, entry.opn.witness, "decommit cannot be nil: Commit(%v)", entry.msg)
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
		copy(cee[:], entry.com.commitment)

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
	c := NewCommitter(sid)
	seen := make(map[string]bool)
	msg := []byte("black lives matter")
	const iterations = 1000

	// Check the pre-computed commitments for uniquness
	for i := 0; i < iterations; i++ {
		// Compute a commitment
		com, _, err := c.Commit(crand.Reader, msg)
		if err != nil {
			t.Error(err)
		}

		// Slices cannot be used as hash keys, so copy into an array
		cee := make([]byte, h().Size())
		copy(cee[:], []byte(com.commitment))

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
		require.Lenf(t, entry.opn.witness, expLen, "nonce has not expected length: %v != %v", len(entry.opn.witness), expLen)
	}
}

// Randomly selected nonces will be unique with overwhelming probability
func TestCommmitProducesDistinctNonces(t *testing.T) {
	t.Parallel()
	c := NewCommitter(sid)
	seen := make(map[string]bool)
	msg := []byte("black lives matter")
	const iterations = 1000

	// Check the pre-computed commitments for uniquness
	for i := 0; i < iterations; i++ {
		// Compute a commitment
		_, opn, err := c.Commit(crand.Reader, msg)
		require.NoError(t, err)

		// Ensure each nonce is unique
		serialised := hex.EncodeToString(opn.witness)
		require.NotContainsf(t, seen, serialised, "duplicate nonce found: %v", opn.witness)
		seen[serialised] = true
	}
}

func TestOpenOnValidCommitments(t *testing.T) {
	testResults := getEntries()
	v := NewVerifier(sid)
	for _, entry := range testResults {
		// Verify each commitment
		err := v.Verify(entry.com, entry.opn)
		// There should be no error
		require.NoErrorf(t, err, "commitment of message failed: %s", entry.msg)
	}
}

func TestOpenOnModifiedNonce(t *testing.T) {
	t.Parallel()
	v := NewVerifier(sid)
	testResults := getEntries()
	for _, entry := range testResults {
		localOpening := entry.opn
		// Modify the nonce MSB
		localOpening.witness[0] ^= 0x80
		// Verify and check for failure
		err := v.Verify(entry.com, localOpening)
		require.True(t, errs.IsVerification(err))
	}
}

func TestOpenOnZeroPrefixNonce(t *testing.T) {
	t.Parallel()
	v := NewVerifier(sid)
	testResults := getEntries()
	for _, entry := range testResults {
		localOpening := entry.opn
		// Modify the nonce
		localOpening.witness[0] = 0x00
		localOpening.witness[1] = 0x00
		localOpening.witness[2] = 0x00
		localOpening.witness[3] = 0x00
		localOpening.witness[4] = 0x00
		localOpening.witness[5] = 0x00
		localOpening.witness[6] = 0x00
		localOpening.witness[7] = 0x00
		localOpening.witness[8] = 0x00
		localOpening.witness[9] = 0x00
		localOpening.witness[10] = 0x00
		// Verify and check for failure
		err := v.Verify(entry.com, localOpening)
		require.True(t, errs.IsVerification(err))
	}
}

// An unrelated message should fail on open
func TestOpenOnNewMessage(t *testing.T) {
	t.Parallel()
	v := NewVerifier(sid)
	testResults := getEntries()
	for _, entry := range testResults {
		localOpening := entry.opn
		// Use a distinct message
		localOpening.message = []byte("no one expects the spanish inquisition")
		// Verify and check for failure
		err := v.Verify(entry.com, localOpening)
		require.True(t, errs.IsVerification(err))
	}
}

// A modified message should fail on open
func TestOpenOnModifiedMessage(t *testing.T) {
	t.Parallel()
	v := NewVerifier(sid)
	testResults := getEntries()
	localTestResults := testResults
	for _, entry := range localTestResults {
		// Skip the empty string message for this test case
		if len(entry.msg) == 0 {
			continue
		}
		localOpening := entry.opn
		// Modify the message LSB
		localOpening.message[0] ^= 0x01
		// Verify and check for failure
		err := v.Verify(entry.com, localOpening)
		require.True(t, errs.IsVerification(err))
	}
}

// A modified commitment should fail on open
func TestOpenOnModifiedCommitment(t *testing.T) {
	t.Parallel()
	v := NewVerifier(sid)
	testResults := getEntries()
	for _, entry := range testResults {
		// Copy and then modify the commitment
		localCommitment := entry.com
		localCommitment.commitment[6] ^= 0x33
		// Verify and check for failure
		err := v.Verify(localCommitment, entry.opn)
		require.True(t, errs.IsVerification(err))
	}
}

// An empty decommit should fail to open
func TestOpenOnDefaultDecommitObject(t *testing.T) {
	t.Parallel()
	v := NewVerifier(sid)
	testResults := getEntries()
	for _, entry := range testResults {
		localOpening := entry.opn
		localOpening.witness = nil
		// OpenWithSession and check for failure
		err := v.Verify(entry.com, localOpening)
		require.True(t, errs.IsArgument(err))
	}
}

// A nil commit should return an error
func TestOpenOnNilCommitment(t *testing.T) {
	t.Parallel()
	v := NewVerifier(sid)
	testResults := getEntries()
	for _, entry := range testResults {
		err := v.Verify(&Commitment{[]byte{}}, entry.opn)
		require.True(t, errs.IsArgument(err))
	}
}

// Too long commitment should produce an error
func TestOpenOnLongCommitment(t *testing.T) {
	t.Parallel()
	v := NewVerifier(sid)
	testResults := getEntries()
	for _, entry := range testResults {
		localCommitment := &Commitment{make([]byte, h().Size()+1)}
		copy(localCommitment.commitment, entry.com.commitment)
		// OpenWithSession and check for failure
		err := v.Verify(localCommitment, entry.opn)
		require.True(t, errs.IsArgument(err))
	}
}

// Too short commitment should produce an error
func TestOpenOnShortCommitment(t *testing.T) {
	t.Parallel()
	v := NewVerifier(sid)
	testResults := getEntries()
	for _, entry := range testResults {
		localCommitment := &Commitment{make([]byte, h().Size()-1)}
		copy(localCommitment.commitment, entry.com.commitment)
		// OpenWithSession and check for failure
		err := v.Verify(localCommitment, entry.opn)
		require.True(t, errs.IsArgument(err))
	}
}
