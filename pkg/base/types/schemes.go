package types

import (
	"fmt"
	"iter"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
)

type Scheme[T ~string] interface {
	Type() T
}

type SchemeElement[T ~string] interface {
	Scheme() Scheme[T]
}

type Participant[S Scheme[T], T ~string] interface {
	Scheme() S
}

type ParticipantIdentifier fmt.Stringer
type Session interface {
	ID() string
}

type AuthenticatedScheme[T ~string] Scheme[T]
type AuthenticatedParticipant[ID ParticipantIdentifier, P AuthenticatedScheme[T], T ~string] interface {
	ID() ID
	Participant[P, T]
}

type MPCScheme[ID ParticipantIdentifier, T ~string] interface {
	Scheme[T]
	AuthenticatedScheme[T]
	AllParticipants() ds.Set[ID]
}

type MPCParticipant[ID ParticipantIdentifier, P MPCScheme[ID, T], T ~string] interface {
	Participant[P, T]
	AuthenticatedParticipant[ID, P, T]
}
type MPCSession[ID ParticipantIdentifier] interface {
	Session
	PresentParticipants() ds.Set[ID]
}

type PermissionedScheme[ID ParticipantIdentifier, T ~string, P any] interface {
	MPCScheme[ID, T]
	IsQualified(claimSet P) error
}

type PermissionedSchemeParticipant[ID ParticipantIdentifier, T ~string, P any] MPCParticipant[ID, PermissionedScheme[ID, T, P], T]

type MonotonicClaimSet[ID ParticipantIdentifier] ds.Set[ID]

type MonotonicScheme[ID ParticipantIdentifier, T ~string] interface {
	PermissionedScheme[ID, T, MonotonicClaimSet[ID]]
	QualifiedSets() iter.Seq[ID]
}

type MonotonicParticipant[ID ParticipantIdentifier, T ~string] PermissionedSchemeParticipant[ID, T, MonotonicClaimSet[ID]]

type Attribute[ID ParticipantIdentifier] func(ID) bool
type AttributeGate[ID ParticipantIdentifier] func(...Attribute[ID]) bool
type Policy[ID ParticipantIdentifier] func(...AttributeGate[ID]) bool
type AttributeClaimSet[ID ParticipantIdentifier] Policy[ID]

type AttributeBasedPermissionedScheme[ID ParticipantIdentifier, T ~string] interface {
	PermissionedScheme[ID, T, AttributeClaimSet[ID]]
	Policies() iter.Seq[Policy[ID]]
}

type AttributeBasedPermissionedParticipant[ID ParticipantIdentifier, T ~string] interface {
	PermissionedSchemeParticipant[ID, T, AttributeClaimSet[ID]]
	Attributes() ds.Set[Attribute[ID]]
}
