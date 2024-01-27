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
//   - For the F^{R_{DL}}_{ZK}, we use ZKP Schnorr made non-interactive with the randomised Fischlim transform.
//   - We use HMAC for realising the Random Oracle Hash function, the key for HMAC is received as input to the protocol.
package bbot

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
)

const label = "COPPER-BATCHED-BASE-OT"

// Sender obtains the 2 random messages for the 1|2 ROT.
type Sender struct {
	ot.Participant

	Output *ot.SenderRotOutput // (s_0, s_1) ∈ [ξ][2][L][κ]bits, the batch of 2 L×κ-bit messages of the 1|2 ROT.

	MyEsk curves.Scalar // MyEsk is my ephemeral secret key.
}

// Receiver chooses one message (with its choice bit) out of the sender's 1|2 ROT messages.
type Receiver struct {
	ot.Participant

	Output *ot.ReceiverRotOutput // (x ∈[ξ]bits, r_x ∈[ξ][L][κ]bits), the batches of choice bits and chosen L×κ-bit messages of the 1|2 ROT.

	MyEsk curves.Scalar // MyEsk is my ephemeral secret key.
}

// NewSender constructs a Random OT sender.
func NewSender(Xi, L int, curve curves.Curve, sid []byte, t transcripts.Transcript, csprng io.Reader) (*Sender, error) {
	participant, err := ot.NewParticipant(Xi, L, curve, sid, label, t, csprng)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "constructing sender")
	}
	return &Sender{
		Output:      &ot.SenderRotOutput{},
		Participant: *participant,
	}, nil
}

// NewReceiver constructs a Random OT receiver.
func NewReceiver(Xi, L int, curve curves.Curve, sid []byte, t transcripts.Transcript, csprng io.Reader) (*Receiver, error) {
	participant, err := ot.NewParticipant(Xi, L, curve, sid, label, t, csprng)
	if err != nil {
		return nil, errs.WrapInvalidArgument(err, "constructing receiver")
	}
	return &Receiver{
		Output:      &ot.ReceiverRotOutput{},
		Participant: *participant,
	}, nil
}
