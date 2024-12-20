package riss_batch_mul

import (
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/riss"
	"github.com/copperexchange/krypton-primitives/pkg/transcripts"
	"io"
	"math/big"
)

var (
	_ types.ThresholdParticipant = (*Participant)(nil)
)

type Participant struct {
	MyIdentityKey      types.IdentityKey
	MySharingId        types.SharingID
	Protocol           types.ThresholdProtocol
	SharingCfg         types.SharingConfig
	Tape               transcripts.Transcript
	Prng               io.Reader
	AllUnqualifiedSets []riss.SharingIdSet
	MyUnqualifiedSets  []riss.SharingIdSet
	Seed               *riss.PseudoRandomSeed
	Rho                map[riss.SharingIdSet]map[riss.SharingIdSet]types.SharingID
	Chi                map[types.SharingID]riss.SharingIdSet
	options            mulSharingOptions
	State              *State
}

type State struct {
	V []*big.Int
	C []*riss.IntShare
}

func NewParticipant(myIdentityKey types.IdentityKey, protocol types.ThresholdProtocol, tape transcripts.Transcript, prng io.Reader, seed *riss.PseudoRandomSeed, sharingOpts ...riss.SharingOpt) (*Participant, error) {
	if myIdentityKey == nil || protocol == nil || tape == nil || prng == nil {
		return nil, errs.NewIsNil("argument is nil")
	}
	if !protocol.Participants().Contains(myIdentityKey) {
		return nil, errs.NewFailed("invalid protocol")
	}
	if protocol.Threshold() < 2 || protocol.TotalParties() < 2 || (protocol.Threshold()-1)*2 >= protocol.TotalParties() {
		return nil, errs.NewFailed("invalid access structure")
	}

	sharingCfg := types.DeriveSharingConfig(protocol.Participants())
	mySharingId, ok := sharingCfg.Reverse().Get(myIdentityKey)
	if !ok {
		return nil, errs.NewFailed("invalid identity key")
	}

	allUnqualifiedSets, err := riss.BuildSortedMaxUnqualifiedSets(protocol.Threshold(), protocol.TotalParties())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to build max unqualified sets")
	}
	rho, err := riss.BuildRhoMapping(allUnqualifiedSets, protocol.TotalParties())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to build rho mapping")
	}
	chi := riss.BuildChiMapping(protocol.Threshold(), protocol.TotalParties())
	//if err != nil {
	//	return nil, errs.WrapFailed(err, "failed to build chi mapping")
	//}
	var myUnqualifiedSets []riss.SharingIdSet
	for _, set := range allUnqualifiedSets {
		if !set.Has(mySharingId) {
			myUnqualifiedSets = append(myUnqualifiedSets, set)
		}
	}
	options := newMulSharingOptions(sharingOpts...)

	p := &Participant{
		MyIdentityKey:      myIdentityKey,
		MySharingId:        mySharingId,
		Protocol:           protocol,
		SharingCfg:         sharingCfg,
		Tape:               tape,
		Prng:               prng,
		Seed:               seed,
		AllUnqualifiedSets: allUnqualifiedSets,
		MyUnqualifiedSets:  myUnqualifiedSets,
		Rho:                rho,
		Chi:                chi,
		options:            options,
		State:              &State{},
	}

	return p, nil
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.MyIdentityKey
}

func (p *Participant) SharingId() types.SharingID {
	return p.MySharingId
}

type mulSharingOptions struct {
	riss.SharingOpts
}

func newMulSharingOptions(opts ...riss.SharingOpt) mulSharingOptions {
	return mulSharingOptions{
		SharingOpts: riss.NewSharingOpts(opts...),
	}
}

func (o *mulSharingOptions) sampleBlinding(prng io.Reader) (*big.Int, error) {
	switch {
	case o.SharingOpts.GetModulus() != nil:
		b, err := crand.Int(prng, o.SharingOpts.GetModulus())
		if err != nil {
			return nil, errs.WrapRandomSample(err, "failed to sample blinding")
		}
		return b, nil
	case o.SharingOpts.GetBitLen() > 0:
		bound := new(big.Int)
		bound.SetBit(bound, int(o.SharingOpts.GetBitLen()+base.ComputationalSecurity), 1)
		b, err := crand.Int(prng, bound)
		if err != nil {
			return nil, errs.WrapRandomSample(err, "failed to sample blinding")
		}
		return b, nil
	default:
		return nil, errs.NewFailed("invalid sharing options")
	}
}

func (o *mulSharingOptions) postProcess(input *big.Int) *big.Int {
	if o.SharingOpts.GetModulus() != nil {
		return new(big.Int).Mod(input, o.SharingOpts.GetModulus())
	}

	return input
}
