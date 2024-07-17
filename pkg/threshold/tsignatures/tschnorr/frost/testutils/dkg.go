package testutils

import (
	crand "crypto/rand"
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/keygen/dkg"
)

var (
	MakeDkgParticipants = testutils.MakeParticipants
	DoDkgRound1 = testutils.DoDkgRound1
	DoDkgRound2 = testutils.DoDkgRound2
)

func MakeParticipants(uniqueSessionId []byte, config types.ThresholdProtocol, identities []types.IdentityKey, prngs []io.Reader) (participants []*dkg.Participant, err error) {

	if len(identities) != int(config.TotalParties()) {
		return nil, errs.NewLength("invalid number of identities %d != %d", len(identities), config.TotalParties())
	}

	participants = make([]*dkg.Participant, config.TotalParties())
	for i, identity := range identities {
		var prng io.Reader
		if len(prngs) != 0 && prngs[i] != nil {
			prng = prngs[i]
		} else {
			prng = crand.Reader
		}

		if !config.Participants().Contains(identity) {
			return nil, errs.NewMissing("given test identity not a participant (problem in tests?)")
		}

		participants[i], err = dkg.NewParticipant(uniqueSessionId, identity.(types.AuthKey), config, prng)
		if err != nil {
			return nil, errs.WrapFailed(err, "could not construct participant")
		}
	}

	return participants, nil
}
