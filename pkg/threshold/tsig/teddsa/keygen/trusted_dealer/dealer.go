package trusted_dealer

import (
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/binrep3"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/teddsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
)

func DealRandom(shareholders ds.Set[sharing.ID], prng io.Reader) (ds.Map[sharing.ID, *teddsa.Shard], error) {
	if shareholders.Size() != 3 {
		return nil, errs.NewValidation("expected 3 shareholders")
	}
	shareholdersList := shareholders.List()
	slices.Sort(shareholdersList)

	var seed [32]byte
	_ = errs2.Must1(io.ReadFull(prng, seed[:]))

	var seedSubShares [3][32]byte
	_ = errs2.Must1(io.ReadFull(prng, seedSubShares[0][:]))
	_ = errs2.Must1(io.ReadFull(prng, seedSubShares[1][:]))
	subtle.XORBytes(seedSubShares[2][:], seedSubShares[0][:], seedSubShares[1][:])
	subtle.XORBytes(seedSubShares[2][:], seedSubShares[2][:], seed[:])

	skBytes := sha512.Sum512(seed[:])
	sk, err := edwards25519.NewScalarField().FromClampedBytes(skBytes[:32])
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create scalar from seed")
	}
	accessStructure, err := feldman.NewAccessStructure(2, shareholders)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create access structure")
	}
	scheme, err := feldman.NewScheme(edwards25519.NewPrimeSubGroup().Generator(), 2, shareholders)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create feldman scheme")
	}
	shareOutput, err := scheme.Deal(feldman.NewSecret(sk), prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot deal shares")
	}

	shards := make(map[sharing.ID]*teddsa.Shard)
	for k := range 3 {
		id := shareholdersList[k]
		var seedShare [4]*binrep3.Share
		for i := range 4 {
			p := binary.BigEndian.Uint64(seedSubShares[(k+2)%3][i*8 : (i+1)*8])
			n := binary.BigEndian.Uint64(seedSubShares[(k+1)%3][i*8 : (i+1)*8])
			seedShare[i] = binrep3.NewShare(id, p, n)
		}
		auxInfo := teddsa.NewAuxiliaryInfo(seedShare)

		skShare, ok := shareOutput.Shares().Get(id)
		if !ok {
			return nil, errs.NewFailed("cannot create share")
		}
		baseShard, err := tschnorr.NewShard(skShare, shareOutput.VerificationMaterial(), accessStructure)
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create base shard")
		}

		shard := &teddsa.Shard{
			*baseShard,
			*auxInfo,
		}
		shards[id] = shard
	}

	return hashmap.NewImmutableComparableFromNativeLike(shards), nil
}
