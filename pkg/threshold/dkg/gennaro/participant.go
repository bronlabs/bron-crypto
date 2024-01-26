package gennaro

import (
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/dlog/batch_schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/pedersen"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"
)

// NothingUpMySleeve
// To get H for Pedersen commitments, we'll hash below to curve. We assume that It is not
// possible to get discrete log of H wrt G designated by a curve. We also assume that the hash
// to curve returns a uniformly random point.
const NothingUpMySleeve = "COPPER_KRYPTON_GENNARO_DKG_SOMETHING_UP_MY_SLEEVE-"

var _ integration.Participant = (*Participant)(nil)

type Participant struct {
	prng io.Reader

	MyAuthKey   integration.AuthKey
	MySharingId int

	CohortConfig           *integration.CohortConfig
	UniqueSessionId        []byte
	sharingIdToIdentityKey map[int]integration.IdentityKey

	H curves.Point

	round int
	state *State

	_ types.Incomparable
}

func (p *Participant) GetAuthKey() integration.AuthKey {
	return p.MyAuthKey
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
	commitmentsProof                 compiler.NIZKPoKProof
	blindedCommitments               []curves.Point
	transcript                       transcripts.Transcript
	secretKeyShare                   curves.Scalar
	receivedBlindedCommitmentVectors map[int][]curves.Point
	partialPublicKeyShares           map[int]curves.Point
	niCompiler                       compiler.NICompiler[batch_schnorr.Statement, batch_schnorr.Witness]

	_ types.Incomparable
}

func NewParticipant(uniqueSessionId []byte, authKey integration.AuthKey, cohortConfig *integration.CohortConfig, niCompilerName compiler.Name, prng io.Reader, transcript transcripts.Transcript) (*Participant, error) {
	err := validateInputs(uniqueSessionId, authKey, cohortConfig, prng)
	if err != nil {
		return nil, errs.NewInvalidArgument("invalid input arguments")
	}

	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KRYPTON_GENNARO_DKG-", nil)
	}
	transcript.AppendMessages("Gennaro DKG Session", uniqueSessionId)

	HMessage, err := hashing.HashChain(sha3.New256, uniqueSessionId, []byte(NothingUpMySleeve))
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "could not produce dlog of H")
	}
	H, err := cohortConfig.CipherSuite.Curve.Hash(HMessage)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "failed to hash to curve for H")
	}

	batchSchnorrProtocol, err := batch_schnorr.NewSigmaProtocol(cohortConfig.CipherSuite.Curve.Generator(), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create batch Schnorr protocol")
	}
	niCompiler, err := compilerUtils.MakeNonInteractive(niCompilerName, batchSchnorrProtocol, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, fmt.Sprintf("cannot create %s compiler", niCompilerName))
	}

	result := &Participant{
		MyAuthKey: authKey,
		state: &State{
			niCompiler: niCompiler,
			transcript: transcript,
		},
		prng:            prng,
		CohortConfig:    cohortConfig,
		H:               H,
		round:           1,
		UniqueSessionId: uniqueSessionId,
	}
	result.sharingIdToIdentityKey, _, result.MySharingId = integration.DeriveSharingIds(authKey, result.CohortConfig.Participants)

	return result, nil
}

func validateInputs(uniqueSessionId []byte, identityKey integration.IdentityKey, cohortConfig *integration.CohortConfig, prng io.Reader) error {
	if err := cohortConfig.Validate(); err != nil {
		return errs.WrapInvalidArgument(err, "cohort config is invalid")
	}
	if cohortConfig.Protocol == nil {
		return errs.NewIsNil("cohort config protocol is nil")
	}
	if prng == nil {
		return errs.NewInvalidArgument("prng is nil")
	}
	if identityKey == nil {
		return errs.NewInvalidArgument("my identity key is nil")
	}
	if !cohortConfig.Participants.Contains(identityKey) {
		return errs.NewInvalidArgument("identity key is not in cohort config")
	}
	if len(uniqueSessionId) == 0 {
		return errs.NewInvalidArgument("invalid session id")
	}
	return nil
}
