//package main
//
//import "C"
//import (
//	crand "crypto/rand"
//	"encoding/hex"
//	"encoding/json"
//	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
//	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
//	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
//	"github.com/copperexchange/crypto-primitives-go/pkg/sharing"
//	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/schnorr"
//	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/frost/keygen/dkg"
//)
//
////type Data struct {
////	value1, value2 int
////}
//
//// var count int
////var test *Data
//
//type identityKey struct {
//	curve *curves.Curve
//	key   *schnorr.PrivateKey
//}
//
//func (k *identityKey) PublicKey() curves.Point {
//	return k.key.PublicKey.Y
//}
//func (k *identityKey) Sign(message []byte) []byte {
//	signature, err := k.key.Sign(crand.Reader, message, nil)
//	if err != nil {
//		panic(err)
//	}
//	result, err := json.Marshal(signature)
//	if err != nil {
//		panic(err)
//	}
//	return result
//}
//
////export Callme
//func Callme() *C.char {
//	curve := curves.ED25519()
//
//	aliceIdentityPrivateKey := schnorr.Keygen(curve, nil, crand.Reader)
//	aliceIdentityKey := &identityKey{
//		curve: curve,
//		key:   aliceIdentityPrivateKey,
//	}
//	bobIdentityPrivateKey := schnorr.Keygen(curve, nil, crand.Reader)
//	bobIdentityKey := &identityKey{
//		curve: curve,
//		key:   bobIdentityPrivateKey,
//	}
//	charlieIdentityPrivateKey := schnorr.Keygen(curve, nil, crand.Reader)
//	charlieIdentityKey := &identityKey{
//		curve: curve,
//		key:   charlieIdentityPrivateKey,
//	}
//
//	cohortConfig := &integration.CohortConfig{
//		Curve:        curve,
//		Protocol:     protocol.FROST,
//		Threshold:    2,
//		TotalParties: 3,
//		Participants: []integration.IdentityKey{aliceIdentityKey, bobIdentityKey, charlieIdentityKey},
//	}
//
//	alice, _ := dkg.NewDKGParticipant(aliceIdentityKey, cohortConfig, crand.Reader)
//	bob, _ := dkg.NewDKGParticipant(bobIdentityKey, cohortConfig, crand.Reader)
//	charlie, _ := dkg.NewDKGParticipant(charlieIdentityKey, cohortConfig, crand.Reader)
//
//	aliceRound1Output, _ := alice.Round1()
//	bobRound1Output, _ := bob.Round1()
//	charlieRound1Output, _ := charlie.Round1()
//
//	aliceRound2Input := map[integration.IdentityKey]*dkg.Round1Broadcast{
//		bobIdentityKey:     bobRound1Output,
//		charlieIdentityKey: charlieRound1Output,
//	}
//	bobRound2Input := map[integration.IdentityKey]*dkg.Round1Broadcast{
//		aliceIdentityKey:   aliceRound1Output,
//		charlieIdentityKey: charlieRound1Output,
//	}
//	charlieRound2Input := map[integration.IdentityKey]*dkg.Round1Broadcast{
//		aliceIdentityKey: aliceRound1Output,
//		bobIdentityKey:   bobRound1Output,
//	}
//
//	aliceRound2OutputBroadcast, aliceRound2OutputP2P, _ := alice.Round2(aliceRound2Input)
//	bobRound2OutputBroadcast, bobRound2OutputP2P, _ := bob.Round2(bobRound2Input)
//	charlieRound2OutputBroadcast, charlieRound2OutputP2P, _ := charlie.Round2(charlieRound2Input)
//
//	aliceRound3InputFromBroadcast := map[integration.IdentityKey]*dkg.Round2Broadcast{
//		bobIdentityKey:     bobRound2OutputBroadcast,
//		charlieIdentityKey: charlieRound2OutputBroadcast,
//	}
//	bobRound3InputFromBroadcast := map[integration.IdentityKey]*dkg.Round2Broadcast{
//		aliceIdentityKey:   aliceRound2OutputBroadcast,
//		charlieIdentityKey: charlieRound2OutputBroadcast,
//	}
//	charlieRound3InputFromBroadcast := map[integration.IdentityKey]*dkg.Round2Broadcast{
//		aliceIdentityKey: aliceRound2OutputBroadcast,
//		bobIdentityKey:   bobRound2OutputBroadcast,
//	}
//
//	aliceRound3InputFromP2P := map[integration.IdentityKey]*dkg.Round2P2P{
//		bobIdentityKey:     bobRound2OutputP2P[aliceIdentityKey],
//		charlieIdentityKey: charlieRound2OutputP2P[aliceIdentityKey],
//	}
//	bobRound3InputFromP2P := map[integration.IdentityKey]*dkg.Round2P2P{
//		aliceIdentityKey:   aliceRound2OutputP2P[bobIdentityKey],
//		charlieIdentityKey: charlieRound2OutputP2P[bobIdentityKey],
//	}
//	charlieRound3InputFromP2P := map[integration.IdentityKey]*dkg.Round2P2P{
//		aliceIdentityKey: aliceRound2OutputP2P[charlieIdentityKey],
//		bobIdentityKey:   bobRound2OutputP2P[charlieIdentityKey],
//	}
//
//	aliceSigningKeyShare, _ := alice.Round3(aliceRound3InputFromBroadcast, aliceRound3InputFromP2P)
//	bobSigningKeyShare, _ := bob.Round3(bobRound3InputFromBroadcast, bobRound3InputFromP2P)
//	charlieSigningKeyShare, _ := charlie.Round3(charlieRound3InputFromBroadcast, charlieRound3InputFromP2P)
//
//	shamirDealer, _ := sharing.NewShamir(2, 3, curve)
//
//	aliceShamirShare := &sharing.ShamirShare{
//		Id:    uint32(alice.MyShamirId),
//		Value: aliceSigningKeyShare.Share.Bytes(),
//	}
//	bobShamirShare := &sharing.ShamirShare{
//		Id:    uint32(bob.MyShamirId),
//		Value: bobSigningKeyShare.Share.Bytes(),
//	}
//	charlieShamirShare := &sharing.ShamirShare{
//		Id:    uint32(charlie.MyShamirId),
//		Value: charlieSigningKeyShare.Share.Bytes(),
//	}
//
//	reconstructedPrivateKey, _ := shamirDealer.Combine(aliceShamirShare, bobShamirShare, charlieShamirShare)
//
//	derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
//
//	return C.CString(hex.EncodeToString(derivedPublicKey.ToAffineCompressed()))
//}
//
//// //export SetValue1
////
////	func SetValue1(a int) {
////		test.value1 = a
////	}
////
//// //export GetValue1
////
////	func GetValue1() int {
////		return test.value1
////	}
//func main() {
//
//}

package main

/*
#include <unistd.h>

typedef void (*callback)(void*);

static void call_later(int delay, callback cb, void* data) {
  sleep(delay);
  cb(data);
}

void call_later_go_cb(void*);
*/
import "C"

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
	"unsafe"

	"github.com/mattn/go-pointer"
)

var count int
var mtx sync.Mutex

type Foo struct {
	v int
}

//export New
func New(a int) unsafe.Pointer {
	f := &Foo{a}

	p := pointer.Save(f)
	//C.call_later(3, C.callback(C.call_later_go_cb), p)

	return p
}

//export call_later_go_cb
func call_later_go_cb(data unsafe.Pointer) {
	f := pointer.Restore(data).(*Foo)
	fmt.Println(f.v)
}

//export Add
func Add(a int, b int64) int {
	//mtx.Lock()
	//defer mtx.Unlock()

	time.Sleep(time.Duration(b) * time.Second)
	count = count + a
	return count
}

//export Cosine
func Cosine(x float64) float64 {
	return math.Cos(x)
}

//export Sort
func Sort(vals []int) {
	sort.Ints(vals)
}

//export Log
func Log() int {
	mtx.Lock()
	defer mtx.Unlock()
	//fmt.Println(msg)
	count++
	return count
}

func main() {}
