// Package vsot implements the "Verified Simplest OT", as defined in "protocol 7" of [DKLs18](https://eprint.iacr.org/2018/499.pdf).
// The original "Simplest OT" protocol is presented in [CC15](https://eprint.iacr.org/2015/267.pdf).
// In our implementation, we run OTs for multiple choice bits in parallel. Furthermore, as described in the DKLs paper,
// we implement this as Random OT protocol. We also add encryption and decryption steps as defined in the protocol, but
// emphasise that these steps are optional. Specifically, in the setting where this OT is used as the seed OT in an
// OT Extension protocol, the encryption and decryption steps are not needed.
//
// Limitation: currently we only support batch OTs that are multiples of 8.
//
// Ideal functionalities:
//   - We have used ZKP Schnorr for the F^{R_{DL}}_{ZK}
//   - We have used HMAC for realising the Random Oracle Hash function, the key for HMAC is received as input to the protocol.
package vsot

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

const (
	// KeyCount is the number of encryption keys created. Since this is a 1-out-of-2 OT, the key count is set to 2.
	KeyCount = 2

	// DigestSize is the length of hash. Similarly, when it comes to encrypting and decryption, it is the size of the
	// plaintext and ciphertext.
	DigestSize = 32
)

type (
	// OneTimePadDecryptionKey is the type of Rho^w, Rho^0, and RHo^1 in the paper.
	OneTimePadDecryptionKey = [DigestSize]byte

	// OneTimePadEncryptionKeys is the type of Rho^0, and RHo^1 in the paper.
	OneTimePadEncryptionKeys = [KeyCount][DigestSize]byte

	// OtChallenge is the type of xi in the paper.
	OtChallenge = [DigestSize]byte

	// OtChallengeResponse is the type of Rho' in the paper.
	OtChallengeResponse = [DigestSize]byte

	// ChallengeOpening is the type of hashed Rho^0 and Rho^1.
	ChallengeOpening = [KeyCount][DigestSize]byte

	// ReceiversMaskedChoices corresponds to the "A" value in the paper in compressed format.
	ReceiversMaskedChoices = []byte
)

// SenderOutput are the outputs that the sender will obtain as a result of running the "random" OT protocol.
type SenderOutput struct {
	// OneTimePadEncryptionKeys are  Rho^0 and Rho^1, the output of the random OT.
	// These can be used to encrypt and send two messages to the receiver.
	// Therefore, for readability they are called OneTimePadEncryptionKeys  in the code.
	OneTimePadEncryptionKeys []OneTimePadEncryptionKeys

	_ helper_types.Incomparable
}

// ReceiverOutput are the outputs that the receiver will obtain as a result of running the "random" OT protocol.
type ReceiverOutput struct {
	// PackedRandomChoiceBits is a packed version of the choice vector, the packing is done for performance reasons.
	PackedRandomChoiceBits []byte

	// RandomChoiceBits is the choice vector represented as unpacked int array. Initialled from PackedRandomChoiceBits.
	RandomChoiceBits []int

	// OneTimePadDecryptionKey is Rho^w, the output of the random OT. For the receiver, there is just 1 output per execution.
	// This value will be used to decrypt one of the messages sent by the sender.
	// Therefore, for readability this is called OneTimePadDecryptionKey in the code.
	OneTimePadDecryptionKey []OneTimePadDecryptionKey

	_ helper_types.Incomparable
}

// Sender stores state for the "sender" role in OT. see Name 7 in Appendix A of DKLs18.
type Sender struct {
	// Output is the output that is produced as a result of running random OT protocol.
	Output *SenderOutput

	Curve curves.Curve

	// SecretKey is the value `b` in the paper, which is the discrete log of B, which will be (re)used in _all_ executions of the OT.
	SecretKey curves.Scalar

	// PublicKey is the public key of the secretKey.
	PublicKey curves.Point

	// BatchSize is the number of parallel OTs.
	BatchSize int

	UniqueSessionId []byte
	transcript      transcripts.Transcript
	prng            io.Reader

	_ helper_types.Incomparable
}

// Receiver stores state for the "receiver" role in OT. Name 7, Appendix A, of DKLs.
type Receiver struct {
	// Output is the output that is produced as a result of running random OT protocol.
	Output *ReceiverOutput

	Curve curves.Curve

	// SenderPublicKey corresponds to "B" in the paper.
	SenderPublicKey curves.Point

	// SenderChallenge is "xi" in the protocol.
	SenderChallenge []OtChallenge

	// BatchSize is the number of parallel OTs.
	BatchSize int

	UniqueSessionId []byte
	transcript      transcripts.Transcript
	prng            io.Reader

	_ helper_types.Incomparable
}

// NewSender creates a new "sender" object, ready to participate in a _random_ verified simplest OT in the role of the sender.
// no messages are specified by the sender, because random ones will be sent (hence the random OT).
// ultimately, the `Sender`'s `Output` field will be appropriately populated.
// you can use it directly, or alternatively bootstrap it into an _actual_ (non-random) OT using `Round7Encrypt` below.
func NewSender(curve curves.Curve, batchSize int, uniqueSessionId []byte, transcript transcripts.Transcript, prng io.Reader) (*Sender, error) {
	if batchSize&0x07 != 0 { // This is the same as `batchSize % 8 != 0`, but is constant time
		return nil, errs.NewInvalidArgument("batch size should be a multiple of 8")
	}
	if prng == nil {
		return nil, errs.NewInvalidArgument("prng is nil")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("KNOX_PRIMITIVES_BASE_OT_SIMPLEST")
	}
	transcript.AppendMessages("session_id", uniqueSessionId)
	transcript.AppendMessages("VSOT", uniqueSessionId)
	return &Sender{
		Output:          &SenderOutput{},
		Curve:           curve,
		BatchSize:       batchSize,
		UniqueSessionId: uniqueSessionId,
		transcript:      transcript,
		prng:            prng,
	}, nil
}

// NewReceiver is a Random OT receiver. Therefore, the choice bits are created randomly.
// The choice bits are stored in a packed format (e.g., each choice is a single bit in a byte array).
func NewReceiver(curve curves.Curve, batchSize int, uniqueSessionId []byte, transcript transcripts.Transcript, prng io.Reader) (*Receiver, error) {
	// This is the same as `batchSize % 8 != 0`, but is constant time
	if batchSize&0x07 != 0 {
		return nil, errs.NewInvalidArgument("batch size should be a multiple of 8")
	}
	if prng == nil {
		return nil, errs.NewInvalidArgument("prng is nil")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript("KNOX_PRIMITIVES_BASE_OT_SIMPLEST")
	}
	transcript.AppendMessages("session_id", uniqueSessionId)
	transcript.AppendMessages("VSOT", uniqueSessionId)

	receiver := &Receiver{
		Output:          &ReceiverOutput{},
		Curve:           curve,
		BatchSize:       batchSize,
		UniqueSessionId: uniqueSessionId,
		transcript:      transcript,
		prng:            prng,
	}
	batchSizeBytes := batchSize >> 3 // divide by 8
	receiver.Output.PackedRandomChoiceBits = make([]byte, batchSizeBytes)
	if _, err := crand.Read(receiver.Output.PackedRandomChoiceBits); err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "choosing random choice bits")
	}
	// Unpack into Choice bits
	receiver.initChoice()
	transcript.AppendMessages("VSOT Receiver", uniqueSessionId)
	return receiver, nil
}

// initChoice initialises the receiver's choice array from the PackedRandomChoiceBits array.
func (receiver *Receiver) initChoice() {
	// unpack the random values in PackedRandomChoiceBits into bits in Choice
	receiver.Output.RandomChoiceBits = make([]int, receiver.BatchSize)
	for i := 0; i < len(receiver.Output.RandomChoiceBits); i++ {
		receiver.Output.RandomChoiceBits[i] = int(bitstring.SelectBit(receiver.Output.PackedRandomChoiceBits, i))
	}
}
