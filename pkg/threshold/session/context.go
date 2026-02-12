package session

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"iter"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
	"github.com/bronlabs/errs-go/errs"
)

const (
	transcriptName                 = "BRON_CRYPTO_SETUP_TRANSCRIPT-"
	transcriptInitLabel            = "BRON_CRYPTO_SETUP_TRANSCRIPT_INIT-"
	seedDomainSeparatorLabel       = "BRON_CRYPTO_SETUP_SEED_DOMAIN_SEPARATOR-"
	subQuorumLabel                 = "BRON_CRYPTO_SETUP_SUBQUORUM-"
	subContextDomainSeparatorLabel = "BRON_CRYPTO_SETUP_SUBCONTEXT-"
)

// Context stores session state such as derived seeds, transcript, and quorum info.
type Context struct {
	sid          network.SID
	id           sharing.ID
	sortedQuorum []sharing.ID
	tape         transcripts.Transcript
	seeds        map[sharing.ID]*sha3.SHAKE
}

// NewContext constructs a session context from the common seed and pairwise seeds.
func NewContext(id sharing.ID, quorum network.Quorum, commonSeed []byte, pairwiseSeeds map[sharing.ID][]byte) (*Context, error) {
	if id < 1 || quorum == nil || pairwiseSeeds == nil || quorum.Size() < 2 || !quorum.Contains(id) {
		return nil, ErrInvalidArgument.WithMessage("invalid arguments")
	}
	for i := range quorum.Iter() {
		if i == id {
			continue
		}
		if _, ok := pairwiseSeeds[i]; !ok {
			return nil, ErrInvalidArgument.WithMessage("missing pairwise seed for %d", i)
		}
	}

	commonImage := sha3.Sum512(commonSeed)
	var sid network.SID
	copy(sid[:], commonImage[:32])
	tape := hagrid.NewTranscript(transcriptName)
	tape.AppendBytes(transcriptInitLabel, commonImage[32:])

	sortedQuorum := slices.Collect(quorum.Iter())
	slices.Sort(sortedQuorum)
	seeds := make(map[sharing.ID]*sha3.SHAKE)
	for _, i := range sortedQuorum {
		if i == id {
			continue
		}

		seeds[i] = sha3.NewCSHAKE256(nil, []byte(seedDomainSeparatorLabel))
		if err := binary.Write(seeds[i], binary.LittleEndian, uint64(min(id, i))); err != nil {
			return nil, errs.Wrap(err).WithMessage("could not write seed")
		}
		if err := binary.Write(seeds[i], binary.LittleEndian, uint64(max(id, i))); err != nil {
			return nil, errs.Wrap(err).WithMessage("could not write seed")
		}
		s := pairwiseSeeds[i]
		if _, err := seeds[i].Write(s); err != nil {
			return nil, errs.Wrap(err).WithMessage("could not write seed")
		}

		// read dummy data to prevent further writes
		if _, err := seeds[i].Read(make([]byte, 32)); err != nil {
			return nil, errs.Wrap(err).WithMessage("could not read seed")
		}
	}

	ctx := &Context{
		sid:          sid,
		id:           id,
		sortedQuorum: sortedQuorum,
		tape:         tape,
		seeds:        seeds,
	}
	return ctx, nil
}

// ID returns the local participant ID.
func (ctx *Context) ID() sharing.ID {
	return ctx.id
}

// SessionID returns the session identifier derived from the common seed.
func (ctx *Context) SessionID() network.SID {
	return ctx.sid
}

// AllPartiesOrdered iterates all parties in sorted quorum order.
func (ctx *Context) AllPartiesOrdered() iter.Seq[sharing.ID] {
	return slices.Values(ctx.sortedQuorum)
}

// OtherPartiesOrdered iterates other parties in sorted quorum order.
func (ctx *Context) OtherPartiesOrdered() iter.Seq[sharing.ID] {
	return func(yield func(sharing.ID) bool) {
		for _, id := range ctx.sortedQuorum {
			if id == ctx.id {
				continue
			}
			if ok := yield(id); !ok {
				return
			}
		}
	}
}

// Transcript returns the session transcript.
func (ctx *Context) Transcript() transcripts.Transcript {
	return ctx.tape
}

// SubContext derives a new context for a subset quorum that includes this participant.
func (ctx *Context) SubContext(subQuorum network.Quorum) (*Context, error) {
	if !subQuorum.IsSubSet(hashset.NewComparable(ctx.sortedQuorum...).Freeze()) || !subQuorum.Contains(ctx.id) {
		return nil, ErrInvalidArgument.WithMessage("new quorum is not a subset of the current quorum")
	}

	subQuorumSorted := slices.Collect(subQuorum.Iter())
	slices.Sort(subQuorumSorted)
	subQuorumData := new(bytes.Buffer)
	if err := binary.Write(subQuorumData, binary.LittleEndian, uint64(subQuorum.Size())); err != nil {
		return nil, errs.Wrap(err).WithMessage("could not write subQuorum size")
	}
	for _, id := range subQuorumSorted {
		if err := binary.Write(subQuorumData, binary.LittleEndian, uint64(id)); err != nil {
			return nil, errs.Wrap(err).WithMessage("could not write subQuorum member")
		}
	}

	subTranscript := ctx.Transcript().Clone()
	subTranscript.AppendBytes(subQuorumLabel, subQuorumData.Bytes())

	subPairwiseSeeds := make(map[sharing.ID]*sha3.SHAKE)
	for _, id := range subQuorumSorted {
		if id == ctx.id {
			continue
		}

		clone := *ctx.seeds[id]
		seed := make([]byte, base.CollisionResistanceBytesCeil)
		if _, err := clone.Read(seed); err != nil {
			return nil, errs.Wrap(err).WithMessage("could not read seed")
		}
		newSeed := sha3.NewCSHAKE256(nil, []byte(subContextDomainSeparatorLabel))
		if _, err := newSeed.Write(seed); err != nil {
			return nil, errs.Wrap(err).WithMessage("could not write seed")
		}
		if _, err := newSeed.Write(subQuorumData.Bytes()); err != nil {
			return nil, errs.Wrap(err).WithMessage("could not write subQuorum data")
		}
		// read dummy data to prevent further writes
		if _, err := newSeed.Read(make([]byte, 32)); err != nil {
			return nil, errs.Wrap(err).WithMessage("could not read seed")
		}
		subPairwiseSeeds[id] = newSeed
	}

	newCtx := &Context{
		sid:          ctx.sid,
		id:           ctx.id,
		sortedQuorum: subQuorumSorted,
		tape:         subTranscript,
		seeds:        subPairwiseSeeds,
	}
	return newCtx, nil
}

// SampleZeroShare derives an additive share that sums to the group identity across the quorum.
func SampleZeroShare[GE algebra.GroupElement[GE]](ctx *Context, g algebra.FiniteGroup[GE]) (*additive.Share[GE], error) {
	value := g.OpIdentity()
	for id := range ctx.OtherPartiesOrdered() {
		v, err := g.Random(ctx.seeds[id])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("could not sample group element")
		}
		if id < ctx.id {
			v = v.OpInv()
		}
		value = value.Op(v)
	}

	as, err := sharing.NewMinimalQualifiedAccessStructure(hashset.NewComparable(ctx.sortedQuorum...).Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create access structure")
	}
	share, err := additive.NewShare(ctx.id, value, as)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create additive share")
	}
	return share, nil
}
