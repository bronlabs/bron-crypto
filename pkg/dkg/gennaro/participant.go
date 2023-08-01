package gennaro

import (
	"io"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/pedersen"
	"github.com/copperexchange/crypto-primitives-go/pkg/transcript"
	"github.com/copperexchange/crypto-primitives-go/pkg/transcript/merlin"
	"github.com/copperexchange/crypto-primitives-go/pkg/zkp/schnorr"
)

// To get H for Pedersen commitments, we'll hash below to curve. We assume that It is not
// possible to get discrete log of H wrt G designated by a curve. We also assume that the hash
// to curve returns a uniformly random point.
const NothingUpMySleeve = "COPPER_KNOX_GENNARO_DKG_SOMETHING_UP_MY_SLEEVE-"

var _ integration.Participant = (*Participant)(nil)

type Participant struct {
	prng io.Reader

	MyIdentityKey integration.IdentityKey
	MyShamirId    int

	CohortConfig          *integration.CohortConfig
	UniqueSessionId       []byte
	shamirIdToIdentityKey map[int]integration.IdentityKey

	H curves.Point

	round int
	state *State
}

func (p *Participant) GetIdentityKey() integration.IdentityKey {
	return p.MyIdentityKey
}

func (p *Participant) GetShamirId() int {
	return p.MyShamirId
}

func (p *Participant) GetCohortConfig() *integration.CohortConfig {
	return p.CohortConfig
}

type State struct {
	myPartialSecretShare             *pedersen.Share
	commitments                      []curves.Point
	blindedCommitments               []curves.Point
	transcript                       transcript.Transcript
	a_i0Proof                        *schnorr.Proof
	secretKeyShare                   curves.Scalar
	receivedBlindedCommitmentVectors map[int][]curves.Point
	partialPublicKeyShares           map[int]curves.Point
	publicKey                        curves.Point
}

func NewParticipant(uniqueSessionId []byte, identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, prng io.Reader, transcript transcript.Transcript) (*Participant, error) {
	if err := cohortConfig.Validate(); err != nil {
		return nil, errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	if transcript == nil {
		transcript = merlin.NewTranscript("COPPER_KNOX_GENNARO_DKG-")
	}
	if uniqueSessionId == nil || len(uniqueSessionId) == 0 {
		return nil, errs.NewInvalidArgument("invalid session id: %s", uniqueSessionId)
	}
	result := &Participant{
		MyIdentityKey: identityKey,
		state: &State{
			transcript: transcript,
		},
		prng:            prng,
		CohortConfig:    cohortConfig,
		H:               cohortConfig.CipherSuite.Curve.Point.Hash([]byte(NothingUpMySleeve)),
		round:           1,
		UniqueSessionId: uniqueSessionId,
	}
	result.shamirIdToIdentityKey, _, result.MyShamirId = integration.DeriveSharingIds(identityKey, result.CohortConfig.Participants)
	transcript.AppendMessage([]byte("Gennaro DKG Session"), uniqueSessionId)
	return result, nil
}
