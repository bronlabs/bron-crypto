package dkg

import (
	"io"

	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler"
	compilerUtils "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler_utils"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts/hagrid"

	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var _ types.ThresholdParticipant = (*Participant[bls12381.G1])(nil)
var _ types.ThresholdParticipant = (*Participant[bls12381.G2])(nil)

type Participant[K bls.KeySubGroup] struct {
	gennaroParty *gennaro.Participant
	inG1         bool
	round        int

	_ ds.Incomparable
}

func (p *Participant[K]) IdentityKey() types.IdentityKey {
	return p.gennaroParty.IdentityKey()
}

func (p *Participant[K]) SharingId() types.SharingID {
	return p.gennaroParty.SharingId()
}

func NewParticipant[K bls.KeySubGroup](uniqueSessionId []byte, authKey types.AuthKey, protocol types.ThresholdProtocol, niCompiler compiler.Name, transcript transcripts.Transcript, prng io.Reader) (*Participant[K], error) {
	err := validateInputs[K](uniqueSessionId, protocol, authKey, niCompiler, prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not validate inputs")
	}

	inG1 := bls12381.GetSourceSubGroup[K]().Name() == bls12381.NameG1
	if (inG1 && protocol.Curve().Name() != bls12381.NameG1) || (!inG1 && protocol.Curve().Name() != bls12381.NameG2) {
		return nil, errs.NewCurve("cohort config curve mismatch with the declared subgroup")
	}
	if transcript == nil {
		transcript = hagrid.NewTranscript("COPPER_KRYPTON_TBLS_KEYGEN-", nil)
	}
	transcript.AppendMessages("threshold bls dkg", uniqueSessionId)
	transcript.AppendMessages("keys subgroup", []byte(protocol.Curve().Name()))
	party, err := gennaro.NewParticipant(uniqueSessionId, authKey, protocol, niCompiler, prng, transcript)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not construct tbls dkg participant out of gennaro dkg participant")
	}
	participant := &Participant[K]{
		gennaroParty: party,
		inG1:         inG1,
		round:        1,
	}

	if err := types.ValidateMPCProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct a dkg participant")
	}

	return participant, nil
}

func validateInputs[K bls.KeySubGroup](uniqueSessionId []byte, protocol types.ThresholdProtocol, authKey types.AuthKey, niCompiler compiler.Name, prng io.Reader) error {
	if len(uniqueSessionId) == 0 {
		return errs.NewIsZero("sid length is zero")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "authKey")
	}
	if prng == nil {
		return errs.NewArgument("prng is nil")
	}
	if err := types.ValidateThresholdProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol config")
	}
	if protocol.Curve().Name() != bls12381.GetSourceSubGroup[K]().Name() {
		return errs.NewArgument("cohort config curve mismatch with the declared subgroup")
	}
	if !compilerUtils.CompilerIsSupported(niCompiler) {
		return errs.NewType("compiler %s is not supported", niCompiler)
	}
	if protocol.Curve().Name() != bls12381.GetSourceSubGroup[K]().Name() {
		return errs.NewArgument(
			"cohort config curve (%s) mismatch with the declared subgroup (%s)",
			protocol.Curve().Name(),
			bls12381.GetSourceSubGroup[K]().Name(),
		)
	}
	return nil
}
