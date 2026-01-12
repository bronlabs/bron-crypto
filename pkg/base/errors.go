package base

import (
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"golang.org/x/exp/constraints"
)

const IdentifiableAbortPartyIDTag = "identifiable_abort_party_id"

var ErrAbort = errs2.New("ABORT")

type IdentifiableAbortID interface {
	constraints.Unsigned
}

func NewIdentifiableAbortError[ID IdentifiableAbortID](partyID ID) errs2.Error {
	return ErrAbort.WithTag(IdentifiableAbortPartyIDTag, partyID)
}

func WrapIdentifiableAbortError[ID IdentifiableAbortID](err error, partyID ID) errs2.Error {
	return errs2.Wrap(err).WithTag(IdentifiableAbortPartyIDTag, partyID)
}

func ShouldAbort(err error) bool {
	return errs2.Is(err, ErrAbort) || IsIdentifiableAbortError(err)
}

func IsIdentifiableAbortError(err error) bool {
	_, is := errs2.HasTag(err, IdentifiableAbortPartyIDTag)
	return is
}

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
