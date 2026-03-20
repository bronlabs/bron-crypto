package session

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"io"
	"iter"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/maputils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/transcripts"
	"github.com/bronlabs/bron-crypto/pkg/transcripts/hagrid"
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
	holderID     sharing.ID
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

		seed := sha3.NewCSHAKE256(nil, []byte(seedDomainSeparatorLabel))
		if err := binary.Write(seed, binary.LittleEndian, uint64(min(id, i))); err != nil {
			return nil, errs.Wrap(err).WithMessage("could not write seed")
		}
		if err := binary.Write(seed, binary.LittleEndian, uint64(max(id, i))); err != nil {
			return nil, errs.Wrap(err).WithMessage("could not write seed")
		}
		s := pairwiseSeeds[i]
		if _, err := seed.Write(s); err != nil {
			return nil, errs.Wrap(err).WithMessage("could not write seed")
		}

		// read dummy data to prevent further writes
		if _, err := seed.Read(make([]byte, 32)); err != nil {
			return nil, errs.Wrap(err).WithMessage("could not read seed")
		}
		seeds[i] = seed
	}

	ctx := &Context{
		sid:          sid,
		holderID:     id,
		sortedQuorum: sortedQuorum,
		tape:         tape,
		seeds:        seeds,
	}
	return ctx, nil
}

// HolderID returns the local participant ID.
func (ctx *Context) HolderID() sharing.ID {
	return ctx.holderID
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
			if id == ctx.holderID {
				continue
			}
			if ok := yield(id); !ok {
				return
			}
		}
	}
}

// Quorum returns the current quorum as an immutable set.
func (ctx *Context) Quorum() ds.Set[sharing.ID] {
	return hashset.NewComparable(ctx.sortedQuorum...).Freeze()
}

// Transcript returns the session transcript.
func (ctx *Context) Transcript() transcripts.Transcript {
	return ctx.tape
}

// SubContext derives a new context for a subset quorum that includes this participant.
func (ctx *Context) SubContext(subQuorum network.Quorum) (*Context, error) {
	if !subQuorum.IsSubSet(hashset.NewComparable(ctx.sortedQuorum...).Freeze()) || !subQuorum.Contains(ctx.holderID) {
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
		if id == ctx.holderID {
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
		holderID:     ctx.holderID,
		sortedQuorum: subQuorumSorted,
		tape:         subTranscript,
		seeds:        subPairwiseSeeds,
	}
	return newCtx, nil
}

func (ctx *Context) Seeds() map[sharing.ID]io.Reader {
	return maputils.MapValues(ctx.seeds, func(_ sharing.ID, shake *sha3.SHAKE) io.Reader { return shake })
}
