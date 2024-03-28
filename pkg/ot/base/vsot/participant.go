package vsot

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
)

// Sender stores state for the "sender" role in OT.
type Sender struct {
	ot.Participant

	Output *ot.SenderRotOutput // (x ∈[ξ]bits, r_x ∈[ξ][L][κ]bits), the batches of choice bits and chosen L×κ-bit messages of the 1|2 ROT.

	SecretKey curves.Scalar                                           // The value `b` in the paper s.t. `b * G = B`, (re)used by all OTs.
	PublicKey curves.Point                                            // PublicKey `B` is the public key of the secretKey.
	dlog      compiler.NICompiler[schnorr.Statement, schnorr.Witness] // compiler used for producing a nizkpok of `b`
}

// Receiver stores state for the "receiver" role in OT.
type Receiver struct {
	ot.Participant

	Output *ot.ReceiverRotOutput // (s_0, s_1) ∈ [ξ][2][L][κ]bits, the batch of 2 L×κ-bit messages of the 1|2 ROT.

	SenderPublicKey curves.Point                                            // SenderPublicKey corresponds to "B" in the paper.
	SenderChallenge []ot.Message                                            // SenderChallenge is "xi" in the protocol.
	dlog            compiler.NICompiler[schnorr.Statement, schnorr.Witness] // compiler used for producing a nizkpok of the dlog of `B`
}

// NewSender creates a new sender for the Random OT protocol.
func NewSender(baseParticipant types.Participant[ot.Protocol], niCompiler compiler.Name) (*Sender, error) {
	participant, err := ot.NewParticipant(baseParticipant, transcriptLabel, 1)
	if err != nil {
		return nil, errs.WrapArgument(err, "constructing sender")
	}
	dlog, err := schnorr.NewSigmaProtocol(baseParticipant.Protocol().Curve().Generator(), baseParticipant.Prng())
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't instantiate dlog protocol")
	}
	nic, err := compilerUtils.MakeNonInteractive(niCompiler, dlog, baseParticipant.Prng())
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't make a non-interactive dlog proof system")
	}
	return &Sender{
		Participant: *participant,
		Output:      &ot.SenderRotOutput{},
		dlog:        nic,
	}, nil
}

// NewReceiver constructs a Random OT receiver.
func NewReceiver(baseParticipant types.Participant[ot.Protocol], niCompiler compiler.Name) (*Receiver, error) {
	participant, err := ot.NewParticipant(baseParticipant, transcriptLabel, 2)
	if err != nil {
		return nil, errs.WrapArgument(err, "constructing receiver")
	}
	choices := make(ot.PackedBits, participant.Protocol().Xi()/8)
	if _, err := io.ReadFull(participant.Prng(), choices); err != nil {
		return nil, errs.WrapRandomSample(err, "generating random choice bits")
	}
	dlog, err := schnorr.NewSigmaProtocol(participant.Protocol().Curve().Generator(), participant.Prng())
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't instantiate dlog protocol")
	}
	nic, err := compilerUtils.MakeNonInteractive(niCompiler, dlog, participant.Prng())
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't make a non-interactive dlog proof system")
	}
	return &Receiver{
		Participant: *participant,
		Output:      &ot.ReceiverRotOutput{},
		dlog:        nic,
	}, nil
}
