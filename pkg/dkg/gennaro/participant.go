package gennaro

import (
	"io"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
	"github.com/copperexchange/knox-primitives/pkg/proofs/dlog/fischlin"
	"github.com/copperexchange/knox-primitives/pkg/sharing/pedersen"
	"github.com/copperexchange/knox-primitives/pkg/transcripts"
	"github.com/copperexchange/knox-primitives/pkg/transcripts/hagrid"
)

// To get H for Pedersen commitments, we'll hash below to curve. We assume that It is not
// possible to get discrete log of H wrt G designated by a curve. We also assume that the hash
// to curve returns a uniformly random point.
const NothingUpMySleeve = "COPPER_KNOX_GENNARO_DKG_SOMETHING_UP_MY_SLEEVE-"

var _ integration.Participant = (*Participant)(nil)

type Participant struct {
	prng io.Reader

	MyIdentityKey integration.IdentityKey
	MySharingId   int

	CohortConfig           *integration.CohortConfig
	UniqueSessionId        []byte
	sharingIdToIdentityKey map[int]integration.IdentityKey

	H curves.Point

	round int
	state *State

	_ helper_types.Incomparable
}

func (p *Participant) GetIdentityKey() integration.IdentityKey {
	return p.MyIdentityKey
}

func (p *Participant) GetSharingId() int {
	return p.MySharingId
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.CohortConfig
}

type State struct {
	myPartialSecretShare             *pedersen.Share
	commitments                      []curves.Point
	blindedCommitments               []curves.Point
	transcript                       transcripts.Transcript
	a_i0Proof                        *fischlin.Proof
	secretKeyShare                   curves.Scalar
	receivedBlindedCommitmentVectors map[int][]curves.Point
	partialPublicKeyShares           map[int]curves.Point

	_ helper_types.Incomparable
}

func NewParticipant(uniqueSessionId []byte, identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, prng io.Reader, transcript transcripts.Transcript) (*Participant, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KNOX_GENNARO_DKG-")
	}
	if len(uniqueSessionId) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", uniqueSessionId)
	}
	result := &Participant{
		MyIdentityKey: identityKey,
		state: &State{
			transcript: transcript,
		},
		prng:            prng,
		CohortConfig:    cohortConfig,
		H:               cohortConfig.CipherSuite.Curve.Point().Hash([]byte(NothingUpMySleeve)),
		round:           1,
		UniqueSessionId: uniqueSessionId,
	}
	result.sharingIdToIdentityKey, _, result.MySharingId = integration.DeriveSharingIds(identityKey, result.CohortConfig.Participants)
	transcript.AppendMessages("Gennaro DKG Session", uniqueSessionId)
	return result, nil
}
