package network

import (
	"crypto/sha3"
	"fmt"
	"hash"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
)

var sidHasher = func() hash.Hash { return sha3.New256() }

type SID [32]byte

func NewSID(xs ...[]byte) (SID, error) {
	digest, err := hashing.Hash(sidHasher, xs...)
	if err != nil {
		return SID{}, errs.WrapHashing(err, "failed to create session ID")
	}
	var sid SID
	copy(sid[:], digest)
	return sid, nil
}

// TODO: remove
type AddressingMethod uint64

// TODO: remove
const (
	Unicast AddressingMethod = iota
	Broadcast
)

// TODO: remove
type Identity interface {
	signatures.PublicKey[Identity]
	fmt.Stringer
}

// TODO: remove
type Node interface {
	// Identity() Identity
}

// TODO: remove
type PKI[N Node] interface {
	Nodes() ds.Set[N]
}

// TODO: remove
type AuthenticationKey signatures.PrivateKey[AuthenticationKey]

// TODO: remove
func NewLocalConfig[P Node](myIdentity P, myAuthKey AuthenticationKey) (*LocalConfig[P], error) {
	if utils.IsNil(myIdentity) {
		return nil, errs.NewIsNil("identity is nil")
	}
	if myAuthKey == nil {
		return nil, errs.NewIsNil("authentication key is nil")
	}
	return &LocalConfig[P]{
		identity:          myIdentity,
		authenticationKey: myAuthKey,
	}, nil
}

// TODO: remove
type LocalConfig[P Node] struct {
	identity          P
	authenticationKey AuthenticationKey
}

func (c *LocalConfig[P]) Identity() P {
	if c == nil {
		return *new(P)
	}
	return c.identity
}

func (c *LocalConfig[P]) AuthenticationKey() AuthenticationKey {
	if c == nil {
		return nil
	}
	return c.authenticationKey
}

type Message any

// TODO: remove
type MessageDeliveryAlgorithm struct {
	DeliveryProtocol string
	IsAuthenticated  bool
}

// TODO: remove
type AuthenticatedMessage[M Message, S signatures.Signature[S]] struct {
	Message   M
	Signature S
}

// TODO: remove
type Network interface {
	Connections() ds.Map[Identity, ds.Set[Identity]]
	IsAuthenticated() bool
}

// TODO: remove
func NewSession[PID Node](id SID, pki PKI[PID], presentParties ds.Set[PID]) (*Session[PID], error) {
	if pki == nil {
		return nil, errs.NewIsNil("pki is nil")
	}
	if presentParties == nil {
		return nil, errs.NewIsNil("present parties is nil")
	}
	if id == (SID{}) {
		return nil, errs.NewIsNil("session ID is empty")
	}
	return &Session[PID]{
		id:             id,
		pki:            pki,
		presentParties: presentParties,
	}, nil
}

// TODO: remove
type Session[PID Node] struct {
	// TODO: add network
	id             SID
	pki            PKI[PID]
	presentParties ds.Set[PID]
}

func (s *Session[_]) ID() SID {
	if s == nil {
		return SID{}
	}
	return s.id
}

func (s *Session[PID]) PKI() PKI[PID] {
	if s == nil {
		return nil
	}
	return s.pki
}

func (s *Session[PID]) PresentParties() ds.Set[PID] {
	if s == nil {
		return nil
	}
	return s.presentParties
}
