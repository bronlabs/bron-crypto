package base

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"golang.org/x/exp/constraints"
)

// IdentifiableAbortPartyIDTag is the tag used to identify parties responsible for an identifiable abort.
const IdentifiableAbortPartyIDTag = "identifiable_abort_party_id"

// ErrAbort indicates that an operation was aborted due to malicious behavior.
var ErrAbort = errs2.New("ABORT")

// IdentifiableAbortID represents the type used for party identifiers in identifiable abort errors.
type IdentifiableAbortID interface {
	constraints.Unsigned
}

// NewIdentifiableAbortError creates a new identifiable abort error for the given party ID.
func NewIdentifiableAbortError[ID IdentifiableAbortID](partyID ID) errs2.Error {
	return ErrAbort.WithTag(IdentifiableAbortPartyIDTag, partyID)
}

// WrapIdentifiableAbortError wraps an existing error as an identifiable abort error for the given party ID.
func WrapIdentifiableAbortError[ID IdentifiableAbortID](err error, partyID ID) errs2.Error {
	return errs2.Wrap(err).WithTag(IdentifiableAbortPartyIDTag, partyID)
}

// ShouldAbort checks if the given error indicates that an operation should be aborted.
func ShouldAbort(err error) bool {
	return errs2.Is(err, ErrAbort) || IsIdentifiableAbortError(err)
}

// IsIdentifiableAbortError checks if the given error is an identifiable abort error.
func IsIdentifiableAbortError(err error) bool {
	_, is := errs2.HasTag(err, IdentifiableAbortPartyIDTag)
	return is
}

// GetMaliciousIdentities extracts the party IDs responsible for an identifiable abort from the given error.
func GetMaliciousIdentities[ID IdentifiableAbortID](err error) []ID {
	culprits := errs2.HasTagAll(err, IdentifiableAbortPartyIDTag)
	ids := make([]ID, len(culprits))
	for i, culprit := range culprits {
		id, ok := culprit.(ID)
		if ok {
			ids[i] = id
		} else {
			panic("identified culprit could not be cast to the expected type")
		}
	}
	return ids
}
