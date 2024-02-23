package aggregation

import (
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost"
)

type Aggregator struct {
	Protocol        types.ThresholdSignatureProtocol
	PublicKey       curves.Point
	MyAuthKey       types.AuthKey
	Quorum          ds.Set[types.IdentityKey]
	SharingConfig   types.SharingConfig
	PublicKeyShares *frost.PublicKeyShares
	Message         []byte

	parameters *SignatureAggregatorParameters

	_ ds.Incomparable
}

func (a *Aggregator) HasIdentifiableAbort() bool {
	return a.PublicKeyShares != nil
}

type SignatureAggregatorParameters struct {
	D_alpha ds.Map[types.IdentityKey, curves.Point]
	E_alpha ds.Map[types.IdentityKey, curves.Point]

	_ ds.Incomparable
}

func (s *SignatureAggregatorParameters) Validate(protocol types.ThresholdSignatureProtocol) error {
	if s == nil {
		return errs.NewIsNil("receiver")
	}
	if s.D_alpha == nil {
		return errs.NewIsNil("D_alpha")
	}
	d_alpha_holders := hashset.NewHashableHashSet(s.D_alpha.Keys()...)
	if !d_alpha_holders.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("set of d alpha holders is not a subset of total participants")
	}
	if s.E_alpha == nil {
		return errs.NewIsNil("E_alpha")
	}
	e_alpha_holders := hashset.NewHashableHashSet(s.E_alpha.Keys()...)
	if !e_alpha_holders.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("set of e alpha holders is not a subset of total participants")
	}
	return nil
}

func NewSignatureAggregator(authKey types.AuthKey, protocol types.ThresholdSignatureProtocol, publicKey curves.Point, publicKeyShares *tsignatures.PartialPublicKeys, quorum ds.Set[types.IdentityKey], message []byte, parameters *SignatureAggregatorParameters) (*Aggregator, error) {
	if err := validateInputs(authKey, protocol, publicKey, publicKeyShares, quorum, message, parameters); err != nil {
		return nil, errs.WrapArgument(err, "invalid arguments")
	}
	sharingConfig := types.DeriveSharingConfig(protocol.Participants())
	aggregator := &Aggregator{
		Protocol:        protocol,
		PublicKey:       publicKey,
		PublicKeyShares: publicKeyShares,
		MyAuthKey:       authKey,
		Quorum:          quorum,
		SharingConfig:   sharingConfig,
		Message:         message,
		parameters:      parameters,
	}
	return aggregator, nil
}

func validateInputs(authKey types.AuthKey, protocol types.ThresholdSignatureProtocol, publicKey curves.Point, publicKeyShares *tsignatures.PartialPublicKeys, quorum ds.Set[types.IdentityKey], message []byte, parameters *SignatureAggregatorParameters) error {
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "auth key")
	}
	if err := types.ValidateThresholdSignatureProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol")
	}
	if publicKey == nil {
		return errs.NewIsNil("public key is nil")
	}
	if publicKey.IsIdentity() {
		return errs.NewIsIdentity("public key")
	}
	if err := publicKeyShares.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "public key shares")
	}
	if quorum == nil {
		return errs.NewIsNil("session participants")
	}
	if !quorum.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("session participant is not a subset of total")
	}
	if len(message) == 0 {
		return errs.NewIsNil("empty messages are not allowed")
	}
	if err := parameters.Validate(protocol); err != nil {
		return errs.WrapValidation(err, "aggregation parameters")
	}
	return nil
}
