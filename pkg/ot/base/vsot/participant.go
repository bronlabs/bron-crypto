package vsot

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/roundbased"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/ot"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
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
func NewSender(myAuthKey types.AuthKey, protocol types.Protocol, Xi, L int, sessionId []byte, niCompiler compiler.Name, transcript transcripts.Transcript, csprng io.Reader) (*Sender, error) {
	participant, err := ot.NewParticipant(myAuthKey, protocol, Xi, L, sessionId, transcriptLabel, transcript, csprng, 1)
	if err != nil {
		return nil, errs.WrapArgument(err, "constructing sender")
	}
	dlog, err := schnorr.NewSigmaProtocol(protocol.Curve().Generator(), csprng)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't instantiate dlog protocol")
	}
	nic, err := compilerUtils.MakeNonInteractive(niCompiler, dlog, csprng)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't make a non-interactive dlog proof system")
	}
	return &Sender{
		Participant: *participant,
		Output:      &ot.SenderRotOutput{},
		dlog:        nic,
	}, nil
}

// NewReceiver is a Random OT receiver. Therefore, the choice bits are sampled randomly.
func NewReceiver(myAuthKey types.AuthKey, protocol types.Protocol, Xi, L int, sessionId []byte, niCompiler compiler.Name, transcript transcripts.Transcript, csprng io.Reader) (*Receiver, error) {
	participant, err := ot.NewParticipant(myAuthKey, protocol, Xi, L, sessionId, transcriptLabel, transcript, csprng, 2)
	if err != nil {
		return nil, errs.WrapArgument(err, "constructing receiver")
	}
	dlog, err := schnorr.NewSigmaProtocol(protocol.Curve().Generator(), csprng)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't instantiate dlog protocol")
	}
	nic, err := compilerUtils.MakeNonInteractive(niCompiler, dlog, csprng)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't make a non-interactive dlog proof system")
	}
	receiver := &Receiver{
		Participant: *participant,
		Output:      &ot.ReceiverRotOutput{},
		dlog:        nic,
	}
	receiver.Output.Choices = make(ot.PackedBits, Xi/8)
	if _, err := io.ReadFull(crand.Reader, receiver.Output.Choices); err != nil {
		return nil, errs.WrapRandomSample(err, "choosing random choice bits")
	}
	return receiver, nil
}

func sendTo[M any](p2p chan<- ds.Map[types.IdentityKey, M], destination types.IdentityKey, m M) {
	p2pMessage := hashmap.NewHashableHashMap[types.IdentityKey, M]()
	p2pMessage.Put(destination, m)
	p2p <- p2pMessage
}

func receiveFrom[M any](p2p <-chan ds.Map[types.IdentityKey, M], source types.IdentityKey) (M, error) {
	p2pMessage := <-p2p
	m, ok := p2pMessage.Get(source)
	if !ok {
		return *new(M), errs.NewFailed("no message")
	}
	return m, nil
}

func (s *Sender) Run(router roundbased.MessageRouter, r *Receiver) error {
	me := s.IdentityKey()
	him := r.IdentityKey()
	r1 := roundbased.NewUnicastRound[*Round1P2P](me, 1, router)
	r2 := roundbased.NewUnicastRound[*Round2P2P](me, 2, router)
	r3 := roundbased.NewUnicastRound[*Round3P2P](me, 3, router)
	r4 := roundbased.NewUnicastRound[*Round4P2P](me, 4, router)
	r5 := roundbased.NewUnicastRound[*Round5P2P](me, 5, router)

	// round 1
	r1Out, err := s.Round1()
	if err != nil {
		return errs.WrapFailed(err, "round 1 failed")
	}
	sendTo(r1.UnicastOut(), him, r1Out)

	// round 3
	r3In, err := receiveFrom(r2.UnicastIn(), him)
	if err != nil {
		return errs.WrapFailed(err, "round 3 failed")
	}
	r3Out, err := s.Round3(r3In)
	if err != nil {
		return errs.WrapFailed(err, "round 3 failed")
	}
	sendTo(r3.UnicastOut(), him, r3Out)

	// round 5
	r5In, err := receiveFrom(r4.UnicastIn(), him)
	if err != nil {
		return errs.WrapFailed(err, "round 5 failed")
	}
	r5Out, err := s.Round5(r5In)
	if err != nil {
		return errs.WrapFailed(err, "round 5 failed")
	}
	sendTo(r5.UnicastOut(), him, r5Out)

	return nil
}

func (r *Receiver) Run(router roundbased.MessageRouter, s *Sender) (*ot.SenderRotOutput, *ot.ReceiverRotOutput, error) {
	me := r.IdentityKey()
	him := s.IdentityKey()
	r1 := roundbased.NewUnicastRound[*Round1P2P](me, 1, router)
	r2 := roundbased.NewUnicastRound[*Round2P2P](me, 2, router)
	r3 := roundbased.NewUnicastRound[*Round3P2P](me, 3, router)
	r4 := roundbased.NewUnicastRound[*Round4P2P](me, 4, router)
	r5 := roundbased.NewUnicastRound[*Round5P2P](me, 5, router)

	// round 2
	r2In, err := receiveFrom(r1.UnicastIn(), him)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "round 2 failed")
	}
	r2Out, err := r.Round2(r2In)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "round 2 failed")
	}
	sendTo(r2.UnicastOut(), him, r2Out)

	// round 4
	r4In, err := receiveFrom(r3.UnicastIn(), him)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "round 4 failed")
	}
	r4Out, err := r.Round4(r4In)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "round 4 failed")
	}
	sendTo(r4.UnicastOut(), him, r4Out)

	// round 6
	r6In, err := receiveFrom(r5.UnicastIn(), him)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "round 6 failed")
	}
	err = r.Round6(r6In)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "round 6 failed")
	}
	return s.Output, r.Output, nil
}
