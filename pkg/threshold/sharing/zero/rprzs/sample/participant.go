package sample

import (
	"sort"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/curveutils"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/csprng"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/zero/rprzs"
)

var _ types.Participant = (*Participant)(nil)

type Participant struct {
	myAuthKey types.AuthKey
	sessionId []byte

	Protocol            types.Protocol
	IdentitySpace       types.IdentitySpace
	PresentParticipants ds.Set[types.IdentityKey]

	Seeds rprzs.PairWiseSeeds
	Prngs ds.Map[types.IdentityKey, csprng.CSPRNG]

	_ ds.Incomparable
}

func (p *Participant) IdentityKey() types.IdentityKey {
	return p.myAuthKey
}

func NewParticipant(sessionId []byte, authKey types.AuthKey, seeds rprzs.PairWiseSeeds, protocol types.Protocol, presentParticipants ds.Set[types.IdentityKey], seededPrngFactory csprng.CSPRNG) (*Participant, error) {
	if err := validateInputs(sessionId, authKey, seeds, protocol, presentParticipants, seededPrngFactory); err != nil {
		return nil, errs.WrapArgument(err, "could not validate inputs")
	}
	identitySpace := types.NewIdentitySpace(protocol.Participants())
	participant := &Participant{
		myAuthKey:           authKey,
		sessionId:           sessionId,
		Protocol:            protocol,
		IdentitySpace:       identitySpace,
		Seeds:               seeds,
		PresentParticipants: presentParticipants,
	}
	// step 3.3 of przs.setup
	if err := participant.createPrngs(seededPrngFactory); err != nil {
		return nil, errs.WrapFailed(err, "could not seed prngs")
	}
	if err := types.ValidateProtocol(participant, protocol); err != nil {
		return nil, errs.WrapValidation(err, "could not construct a valid sampler")
	}
	return participant, nil
}

func validateInputs(sessionId []byte, authKey types.AuthKey, seeds rprzs.PairWiseSeeds, protocol types.Protocol, presentParticipants ds.Set[types.IdentityKey], seededPrngFactory csprng.CSPRNG) error {
	if len(sessionId) == 0 {
		return errs.NewIsZero("sessionId length is zero")
	}
	if err := types.ValidateAuthKey(authKey); err != nil {
		return errs.WrapValidation(err, "authKey")
	}
	if err := types.ValidateProtocolConfig(protocol); err != nil {
		return errs.WrapValidation(err, "protocol")
	}
	if presentParticipants.Size() < 2 {
		return errs.NewSize("need at least 2 participants")
	}
	if !presentParticipants.IsSubSet(protocol.Participants()) {
		return errs.NewSize("present sampler set is not a subset of all participants")
	}
	if seeds == nil {
		return errs.NewIsNil("seeds")
	}
	seeders := hashset.NewHashableHashSet(seeds.Keys()...)
	if !seeders.IsSubSet(protocol.Participants()) {
		return errs.NewMembership("we have seeds from people who are not a participant in this protocol")
	}
	for _, value := range seeds.Iter() {
		if ct.SliceIsZero(value[:]) == 1 {
			return errs.NewIsZero("found seed that's all zero")
		}
	}
	if seededPrngFactory == nil {
		return errs.NewIsNil("seeded prng factory")
	}
	if !curveutils.AllIdentityKeysWithSameCurve(authKey.PublicKey().Curve(), protocol.Participants().List()...) {
		return errs.NewCurve("authKey and participants have different curves")
	}
	if !curveutils.AllIdentityKeysWithSameCurve(authKey.PublicKey().Curve(), presentParticipants.List()...) {
		return errs.NewCurve("authKey and presentParticipants have different curves")
	}
	if !curveutils.AllIdentityKeysWithSameCurve(authKey.PublicKey().Curve(), seeders.List()...) {
		return errs.NewCurve("authKey and seeders have different curves")
	}
	return nil
}

// CreatePrngs creates and seed the PRNGs for this participant with the pairwise seeds.
func (p *Participant) createPrngs(seededPrng csprng.CSPRNG) error {
	p.Prngs = hashmap.NewHashableHashMap[types.IdentityKey, csprng.CSPRNG]()
	sortedParticipants := types.ByPublicKey(p.PresentParticipants.List())
	sort.Sort(sortedParticipants)
	for _, participant := range sortedParticipants {
		if participant.Equal(p.IdentityKey()) {
			continue
		}
		i, exists := p.IdentitySpace.Reverse().Get(participant)
		if !exists {
			return errs.NewMissing("could not find index of participant %x", participant.String())
		}
		sharedSeed, exists := p.Seeds.Get(participant)
		if !exists {
			return errs.NewMissing("could not find shared seed for index %d", i)
		}
		salt, err := hashing.HashPrefixedLength(base.RandomOracleHashFunction, p.sessionId)
		if err != nil {
			return errs.WrapHashing(err, "could not seed PRNG for index %d", i)
		}
		prng, err := seededPrng.New(sharedSeed[:], salt)
		if err != nil {
			return errs.WrapFailed(err, "could not seed PRNG for index %d", i)
		}
		p.Prngs.Put(participant, prng)
	}
	return nil
}
