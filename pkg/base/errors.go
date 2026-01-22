package base

import (
	"golang.org/x/exp/constraints"

	"github.com/bronlabs/errs-go/pkg/errs"
)

// IdentifiableAbortPartyIDTag is the tag used to identify parties responsible for an identifiable abort.
const IdentifiableAbortPartyIDTag = "identifiable_abort_party_id"

// ErrAbort indicates that an operation was aborted due to malicious behaviour.
var ErrAbort = errs.New("ABORT")

// IdentifiableAbortID represents the type used for party identifiers in identifiable abort errors.
type IdentifiableAbortID interface {
	constraints.Unsigned
}

// ShouldAbort checks if the given error indicates that an operation should be aborted.
func ShouldAbort(err error) bool {
	return errs.Is(err, ErrAbort) || IsIdentifiableAbortError(err)
}

// IsIdentifiableAbortError checks if the given error is an identifiable abort error.
func IsIdentifiableAbortError(err error) bool {
	_, is := errs.HasTag(err, IdentifiableAbortPartyIDTag)
	return is
}

// GetMaliciousIdentities extracts the party IDs responsible for an identifiable abort from the given error.
func GetMaliciousIdentities[ID IdentifiableAbortID](err error) []ID {
	culprits := errs.HasTagAll(err, IdentifiableAbortPartyIDTag)
	ids := make([]ID, len(culprits))
	for i, culprit := range culprits {
		id, ok := culprit.(ID)
		if ok {
			ids[i] = id
		}
	}
	return ids
}
