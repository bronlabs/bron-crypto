package jf

import (
	"encoding/hex"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
)

func RunDkg(participant *Participant, comm stack.ProtocolClient) (*tsignatures.SigningKeyShare, *tsignatures.PartialPublicKeys, error) {
	const roundPrefixLabel = "GennaroDKG"
	roundPrefixBytes, err := participant.Transcript.ExtractBytes(roundPrefixLabel, 16)
	if err != nil {
		return nil, nil, err
	}
	round1 := fmt.Sprintf("%s_GennaroDKG_R1", hex.EncodeToString(roundPrefixBytes[:]))
	round2 := fmt.Sprintf("%s_GennaroDKG_R2", hex.EncodeToString(roundPrefixBytes[:]))

	coparties := participant.Protocol.Participants().Clone()
	coparties.Remove(participant.IdentityKey())

	// Round 1
	r1bo, r1uo, err := participant.Round1()
	if err != nil {
		return nil, nil, err
	}
	stack.RoundSend(comm, round1, r1bo, r1uo)

	// Round 2
	r2bi, r2ui := stack.RoundReceive[*Round1Broadcast, *Round1P2P](comm, round1, coparties, coparties)
	r2bo, err := participant.Round2(r2bi, r2ui)
	if err != nil {
		return nil, nil, err
	}
	stack.RoundSendBroadcastOnly(comm, round2, r2bo)

	// Round 3
	r3bi := stack.RoundReceiveBroadcastOnly[*Round2Broadcast](comm, round2, coparties)
	keyShare, partialPublicKeys, err := participant.Round3(r3bi)
	if err != nil {
		return nil, nil, err
	}

	return keyShare, partialPublicKeys, nil
}
