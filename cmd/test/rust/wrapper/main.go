package main

/*
#include <unistd.h>
#include <stdlib.h>

typedef void (*callback)(void*);

static void call_later(int delay, callback cb, void* data) {
  sleep(delay);
  cb(data);
}

void call_later_go_cb(void*);

struct Round2Output {
    void* broadcast;
    void* p2p;
};

struct Foo {
	void* participant;
	int error_code;
};
*/
import "C"
import (
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/schnorr"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/keygen/dkg"
	"github.com/mattn/go-pointer"
	"unsafe"
)

type identityKey struct {
	curve *curves.Curve
	key   *schnorr.PrivateKey
}

func (k *identityKey) PublicKey() curves.Point {
	return k.key.PublicKey.Y
}
func (k *identityKey) Sign(message []byte) []byte {
	signature, err := k.key.Sign(crand.Reader, message, nil)
	if err != nil {
		panic(err)
	}
	result, err := json.Marshal(signature)
	if err != nil {
		panic(err)
	}
	return result
}

//export DKG_FROST_CreateIdentity
func DKG_FROST_CreateIdentity() unsafe.Pointer {
	curve := curves.ED25519()

	identityPrivateKey := schnorr.Keygen(curve, nil, crand.Reader)
	identityKey := &identityKey{
		curve: curve,
		key:   identityPrivateKey,
	}

	p := pointer.Save(identityKey)

	return p
}

//export DKG_FROST_CreateCohortConfig
func DKG_FROST_CreateCohortConfig(alice unsafe.Pointer, bob unsafe.Pointer, charlie unsafe.Pointer) unsafe.Pointer {
	curve := curves.ED25519()

	aliceIdentityKey := pointer.Restore(alice).(integration.IdentityKey)
	bobIdentityKey := pointer.Restore(bob).(integration.IdentityKey)
	charlieIdentityKey := pointer.Restore(charlie).(integration.IdentityKey)

	cohortConfig := &integration.CohortConfig{
		Curve:        curve,
		Protocol:     protocol.FROST,
		Threshold:    2,
		TotalParties: 3,
		Participants: []integration.IdentityKey{aliceIdentityKey, bobIdentityKey, charlieIdentityKey},
	}

	p := pointer.Save(cohortConfig)

	return p
}

//export DKG_FROST_NewDKGParticipant
func DKG_FROST_NewDKGParticipant(identityKeyP unsafe.Pointer, cohortConfigP unsafe.Pointer) (unsafe.Pointer, *C.char) {
	identityKey := pointer.Restore(identityKeyP).(integration.IdentityKey)
	cohortConfig := pointer.Restore(cohortConfigP).(*integration.CohortConfig)

	participant, err := dkg.NewDKGParticipant(identityKey, cohortConfig, crand.Reader)
	if err != nil {
		return nil, C.CString(err.Error())
	}

	p := pointer.Save(participant)

	return p, C.CString("")
}

//export DKG_FROST_Round1
func DKG_FROST_Round1(participantP unsafe.Pointer) unsafe.Pointer {
	participant := pointer.Restore(participantP).(*dkg.DKGParticipant)

	round1Output, _ := participant.Round1()

	p := pointer.Save(round1Output)

	return p
}

//export DKG_FROST_Round2
func DKG_FROST_Round2(participantP unsafe.Pointer, player2P unsafe.Pointer, player3P unsafe.Pointer, player2Output unsafe.Pointer, player3Output unsafe.Pointer) C.struct_Round2Output {
	participant := pointer.Restore(participantP).(*dkg.DKGParticipant)

	player2IdentityKey := pointer.Restore(player2P).(integration.IdentityKey)
	player3IdentityKey := pointer.Restore(player3P).(integration.IdentityKey)

	player2Round1Output := pointer.Restore(player2Output).(*dkg.Round1Broadcast)
	player3Round1Output := pointer.Restore(player3Output).(*dkg.Round1Broadcast)

	participantRound2Input := map[integration.IdentityKey]*dkg.Round1Broadcast{
		player2IdentityKey: player2Round1Output,
		player3IdentityKey: player3Round1Output,
	}

	participantRound2OutputBroadcast, participantRound2OutputP2P, _ := participant.Round2(participantRound2Input)

	broadcastP := pointer.Save(participantRound2OutputBroadcast)
	P2PP := pointer.Save(participantRound2OutputP2P)

	return C.struct_Round2Output{broadcast: broadcastP, p2p: P2PP}
}

//export DKG_FROST_Round3
func DKG_FROST_Round3(
	participantP unsafe.Pointer,
	player2P unsafe.Pointer,
	player3P unsafe.Pointer,
	player2OutputBroadcastP unsafe.Pointer,
	player3OutputBroadcastP unsafe.Pointer,
	player2OutputP2PP unsafe.Pointer,
	player3OutputP2PP unsafe.Pointer,
) *C.char {
	participant := pointer.Restore(participantP).(*dkg.DKGParticipant)

	player2IdentityKey := pointer.Restore(player2P).(integration.IdentityKey)
	player3IdentityKey := pointer.Restore(player3P).(integration.IdentityKey)

	player2OutputBroadcast := pointer.Restore(player2OutputBroadcastP).(*dkg.Round2Broadcast)
	player3OutputBroadcast := pointer.Restore(player3OutputBroadcastP).(*dkg.Round2Broadcast)

	participantRound2Input := map[integration.IdentityKey]*dkg.Round2Broadcast{
		player2IdentityKey: player2OutputBroadcast,
		player3IdentityKey: player3OutputBroadcast,
	}

	player2OutputP2P := pointer.Restore(player2OutputP2PP).(map[integration.IdentityKey]*dkg.Round2P2P)
	player3OutputP2P := pointer.Restore(player3OutputP2PP).(map[integration.IdentityKey]*dkg.Round2P2P)

	participantRound3InputFromP2P := map[integration.IdentityKey]*dkg.Round2P2P{
		player2IdentityKey: player2OutputP2P[participant.MyIdentityKey],
		player3IdentityKey: player3OutputP2P[participant.MyIdentityKey],
	}

	participantSigningKeyShare, _ := participant.Round3(participantRound2Input, participantRound3InputFromP2P)

	return C.CString(hex.EncodeToString(participantSigningKeyShare.PublicKey.ToAffineCompressed()))
}

//export UnrefPointer
func UnrefPointer(p unsafe.Pointer) {
	pointer.Unref(p)
}

//export UnrefString
func UnrefString(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

func Callme() *C.char {
	curve := curves.ED25519()

	aliceIdentityPrivateKey := schnorr.Keygen(curve, nil, crand.Reader)
	aliceIdentityKey := &identityKey{
		curve: curve,
		key:   aliceIdentityPrivateKey,
	}
	bobIdentityPrivateKey := schnorr.Keygen(curve, nil, crand.Reader)
	bobIdentityKey := &identityKey{
		curve: curve,
		key:   bobIdentityPrivateKey,
	}
	charlieIdentityPrivateKey := schnorr.Keygen(curve, nil, crand.Reader)
	charlieIdentityKey := &identityKey{
		curve: curve,
		key:   charlieIdentityPrivateKey,
	}

	cohortConfig := &integration.CohortConfig{
		Curve:        curve,
		Protocol:     protocol.FROST,
		Threshold:    2,
		TotalParties: 3,
		Participants: []integration.IdentityKey{aliceIdentityKey, bobIdentityKey, charlieIdentityKey},
	}

	alice, _ := dkg.NewDKGParticipant(aliceIdentityKey, cohortConfig, crand.Reader)
	bob, _ := dkg.NewDKGParticipant(bobIdentityKey, cohortConfig, crand.Reader)
	charlie, _ := dkg.NewDKGParticipant(charlieIdentityKey, cohortConfig, crand.Reader)

	aliceRound1Output, _ := alice.Round1()
	bobRound1Output, _ := bob.Round1()
	charlieRound1Output, _ := charlie.Round1()

	aliceRound2Input := map[integration.IdentityKey]*dkg.Round1Broadcast{
		bobIdentityKey:     bobRound1Output,
		charlieIdentityKey: charlieRound1Output,
	}
	bobRound2Input := map[integration.IdentityKey]*dkg.Round1Broadcast{
		aliceIdentityKey:   aliceRound1Output,
		charlieIdentityKey: charlieRound1Output,
	}
	charlieRound2Input := map[integration.IdentityKey]*dkg.Round1Broadcast{
		aliceIdentityKey: aliceRound1Output,
		bobIdentityKey:   bobRound1Output,
	}

	aliceRound2OutputBroadcast, aliceRound2OutputP2P, _ := alice.Round2(aliceRound2Input)
	bobRound2OutputBroadcast, bobRound2OutputP2P, _ := bob.Round2(bobRound2Input)
	charlieRound2OutputBroadcast, charlieRound2OutputP2P, _ := charlie.Round2(charlieRound2Input)

	aliceRound3InputFromBroadcast := map[integration.IdentityKey]*dkg.Round2Broadcast{
		bobIdentityKey:     bobRound2OutputBroadcast,
		charlieIdentityKey: charlieRound2OutputBroadcast,
	}
	bobRound3InputFromBroadcast := map[integration.IdentityKey]*dkg.Round2Broadcast{
		aliceIdentityKey:   aliceRound2OutputBroadcast,
		charlieIdentityKey: charlieRound2OutputBroadcast,
	}
	charlieRound3InputFromBroadcast := map[integration.IdentityKey]*dkg.Round2Broadcast{
		aliceIdentityKey: aliceRound2OutputBroadcast,
		bobIdentityKey:   bobRound2OutputBroadcast,
	}

	aliceRound3InputFromP2P := map[integration.IdentityKey]*dkg.Round2P2P{
		bobIdentityKey:     bobRound2OutputP2P[aliceIdentityKey],
		charlieIdentityKey: charlieRound2OutputP2P[aliceIdentityKey],
	}
	bobRound3InputFromP2P := map[integration.IdentityKey]*dkg.Round2P2P{
		aliceIdentityKey:   aliceRound2OutputP2P[bobIdentityKey],
		charlieIdentityKey: charlieRound2OutputP2P[bobIdentityKey],
	}
	charlieRound3InputFromP2P := map[integration.IdentityKey]*dkg.Round2P2P{
		aliceIdentityKey: aliceRound2OutputP2P[charlieIdentityKey],
		bobIdentityKey:   bobRound2OutputP2P[charlieIdentityKey],
	}

	aliceSigningKeyShare, _ := alice.Round3(aliceRound3InputFromBroadcast, aliceRound3InputFromP2P)
	bobSigningKeyShare, _ := bob.Round3(bobRound3InputFromBroadcast, bobRound3InputFromP2P)
	charlieSigningKeyShare, _ := charlie.Round3(charlieRound3InputFromBroadcast, charlieRound3InputFromP2P)

	shamirDealer, _ := sharing.NewShamir(2, 3, curve)

	aliceShamirShare := &sharing.ShamirShare{
		Id:    uint32(alice.MyShamirId),
		Value: aliceSigningKeyShare.Share.Bytes(),
	}
	bobShamirShare := &sharing.ShamirShare{
		Id:    uint32(bob.MyShamirId),
		Value: bobSigningKeyShare.Share.Bytes(),
	}
	charlieShamirShare := &sharing.ShamirShare{
		Id:    uint32(charlie.MyShamirId),
		Value: charlieSigningKeyShare.Share.Bytes(),
	}

	reconstructedPrivateKey, _ := shamirDealer.Combine(aliceShamirShare, bobShamirShare, charlieShamirShare)

	derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)

	return C.CString(hex.EncodeToString(derivedPublicKey.ToAffineCompressed()))
}

func main() {}
