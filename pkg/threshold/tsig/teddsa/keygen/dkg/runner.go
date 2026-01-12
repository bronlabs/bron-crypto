package dkg

import (
	"encoding/binary"
	"io"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials"
	"github.com/bronlabs/bron-crypto/pkg/base/polynomials/interpolation"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/network/exchange"
	"github.com/bronlabs/bron-crypto/pkg/threshold/mpc"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/binrep3"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/feldman"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/teddsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/teddsa/keygen/dkg/circuits"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
)

type Runner struct {
	party *Participant

	quorumList []sharing.ID
}

func NewRunner(sid network.SID, id sharing.ID, quorum network.Quorum, prng io.Reader) (network.Runner[*teddsa.Shard], error) {
	party, err := NewParticipant(sid, id, quorum, prng)
	if err != nil {
		return nil, errs.WrapValidation(err, "cannot create runner")
	}

	quorumList := party.quorum.List()
	slices.Sort(quorumList)
	r := &Runner{
		party:      party,
		quorumList: quorumList,
	}
	return r, nil
}

func (r *Runner) Run(rt *network.Router) (*teddsa.Shard, error) {
	arith, err := mpc.NewArithmetic(rt, r.party.sid, "EdDSA-DKG:", r.party.sharingId, r.party.quorum, r.party.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create arithmetic")
	}

	seed, digest := circuits.Sha512(arith)
	seedShare, err := r.makeSeedShare(arith, seed)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot make seed share")
	}
	auxInfo := teddsa.NewAuxiliaryInfo(seedShare)

	skShareP, skShareN, skShareValue, err := r.makeSecretKeyShareValues(arith, digest)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot make secret key share values")
	}
	ac, err := feldman.NewAccessStructure(2, r.party.quorum)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create access structure")
	}
	skShare, err := feldman.NewShare(r.party.sharingId, skShareValue, ac)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create share")
	}

	fv, err := r.makePartialPublicKeyValues(rt, skShareP, skShareN)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot make partial public key values")
	}

	baseShard, err := tschnorr.NewShard[*edwards25519.PrimeSubGroupPoint, *edwards25519.Scalar](skShare, fv, ac)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create tSchnorr shard from DKG output")
	}
	shard := &teddsa.Shard{
		Shard:         *baseShard,
		AuxiliaryInfo: *auxInfo,
	}

	return shard, nil
}

func (r *Runner) makeSeedShare(arith *mpc.Arithmetic, seed [4]*mpc.Value64) ([4]*binrep3.Share, error) {
	var err error

	pi := make([]mpc.Ed25519Scalar, 3)
	pi[0] = [4]*mpc.Value64{
		arith.RandomSecret(),
		arith.RandomSecret(),
		arith.RandomSecret(),
		arith.RandomSecret(),
	}
	pi[1] = [4]*mpc.Value64{
		arith.RandomSecret(),
		arith.RandomSecret(),
		arith.RandomSecret(),
		arith.RandomSecret(),
	}
	pi[2] = [4]*mpc.Value64{
		arith.Xor(arith.Xor(seed[0], pi[0][0]), pi[1][0]),
		arith.Xor(arith.Xor(seed[1], pi[0][1]), pi[1][1]),
		arith.Xor(arith.Xor(seed[2], pi[0][2]), pi[1][2]),
		arith.Xor(arith.Xor(seed[3], pi[0][3]), pi[1][3]),
	}

	// these maps will have only one non-nil value if everything went well
	piPrevs := make(map[sharing.ID][]uint64)
	piNexts := make(map[sharing.ID][]uint64)
	for k := range 3 {
		piPrevs[r.quorumList[k]], err = arith.RevealTo(r.quorumList[k], pi[r.prevIdx(k)][:]...)
		if err != nil {
			return [4]*binrep3.Share{}, errs.WrapFailed(err, "cannot reveal pi")
		}
		piNexts[r.quorumList[k]], err = arith.RevealTo(r.quorumList[k], pi[r.nextIdx(k)][:]...)
		if err != nil {
			return [4]*binrep3.Share{}, errs.WrapFailed(err, "cannot reveal pi")
		}
	}

	preimageShare := [4]*binrep3.Share{
		binrep3.NewShare(r.party.sharingId, piPrevs[r.party.sharingId][0], piNexts[r.party.sharingId][0]),
		binrep3.NewShare(r.party.sharingId, piPrevs[r.party.sharingId][1], piNexts[r.party.sharingId][1]),
		binrep3.NewShare(r.party.sharingId, piPrevs[r.party.sharingId][2], piNexts[r.party.sharingId][2]),
		binrep3.NewShare(r.party.sharingId, piPrevs[r.party.sharingId][3], piNexts[r.party.sharingId][3]),
	}
	return preimageShare, nil
}

func (r *Runner) makeSecretKeyShareValues(arith *mpc.Arithmetic, image [8]*mpc.Value64) (*edwards25519.Scalar, *edwards25519.Scalar, *edwards25519.Scalar, error) {
	var err error
	ed25519Arith := mpc.NewEd25519Arithmetic(arith)
	skBytes := [4]*mpc.Value64{
		arith.And(image[0].ReverseBytes(), mpc.NewValue64Public(0xfffffffffffffff8)),
		image[1].ReverseBytes(),
		image[2].ReverseBytes(),
		arith.Xor(arith.And(image[3].ReverseBytes(), mpc.NewValue64Public(0x3fffffffffffffff)), mpc.NewValue64Public(0x4000000000000000)),
	}
	sk := ed25519Arith.U256ReduceToScalar(skBytes)
	ski := make([]mpc.Ed25519Scalar, 3)
	ski[0] = ed25519Arith.ScalarRandom()
	ski[1] = ed25519Arith.ScalarRandom()
	ski[2] = ed25519Arith.ScalarSub(ed25519Arith.ScalarSub(sk, ski[0]), ski[1])

	skPrevs := make(map[sharing.ID][]uint64)
	skNexts := make(map[sharing.ID][]uint64)
	for k := range 3 {
		skPrevs[r.quorumList[k]], err = arith.RevealTo(r.quorumList[k], ski[r.prevIdx(k)][:]...)
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "cannot reveal ski")
		}
		skNexts[r.quorumList[k]], err = arith.RevealTo(r.quorumList[k], ski[r.nextIdx(k)][:]...)
		if err != nil {
			return nil, nil, nil, errs.WrapFailed(err, "cannot reveal ski")
		}
	}

	var skpBytes []byte
	var sknBytes []byte
	for k := 3; k >= 0; k-- {
		skpBytes = binary.BigEndian.AppendUint64(skpBytes, skPrevs[r.party.sharingId][k])
		sknBytes = binary.BigEndian.AppendUint64(sknBytes, skNexts[r.party.sharingId][k])
	}

	skp, err := edwards25519.NewScalarField().FromBytes(skpBytes)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "cannot create scalar from prev")
	}
	skn, err := edwards25519.NewScalarField().FromBytes(sknBytes)
	if err != nil {
		return nil, nil, nil, errs.WrapFailed(err, "cannot create scalar from next")
	}

	field := edwards25519.NewScalarField()
	skShareP, err := interpolation.InterpolateAt(
		[]*edwards25519.Scalar{field.Zero(), field.FromUint64(uint64(r.prevId(r.party.sharingId)))},
		[]*edwards25519.Scalar{skp, field.Zero()},
		field.FromUint64(uint64(r.party.sharingId)),
	)
	skShareN, err := interpolation.InterpolateAt(
		[]*edwards25519.Scalar{field.Zero(), field.FromUint64(uint64(r.nextId(r.party.sharingId)))},
		[]*edwards25519.Scalar{skn, field.Zero()},
		field.FromUint64(uint64(r.party.sharingId)),
	)

	skShareValue := skShareP.Add(skShareN)
	return skp, skn, skShareValue, nil
}

func (r *Runner) makePartialPublicKeyValues(rt *network.Router, skP, skN *edwards25519.Scalar) (feldman.VerificationVector[*edwards25519.PrimeSubGroupPoint, *edwards25519.Scalar], error) {
	partialPublicKeys := make(map[sharing.ID]*edwards25519.PrimeSubGroupPoint)
	partialPublicKeys[r.prevId(r.party.sharingId)] = edwards25519.NewPrimeSubGroup().ScalarBaseMul(skP)
	partialPublicKeys[r.nextId(r.party.sharingId)] = edwards25519.NewPrimeSubGroup().ScalarBaseMul(skN)
	ppkMessage := &RoundPartialPublicKeyBroadcast{
		P: partialPublicKeys[r.prevId(r.party.sharingId)],
		N: partialPublicKeys[r.nextId(r.party.sharingId)],
	}
	receivedPpkMessages, err := exchange.ExchangeBroadcast(rt, "RoundCommitPk", ppkMessage)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot exchange commit messages")
	}

	for id := range r.party.quorum.Iter() {
		if id == r.party.sharingId {
			continue
		}

		m, ok := receivedPpkMessages.Get(id)
		if !ok {
			return nil, errs.NewFailed("missing commit message")
		}
		if ppk, ok := partialPublicKeys[r.prevId(id)]; ok {
			if !ppk.Equal(m.P) {
				return nil, errs.NewFailed("inconsistent commit message")
			}
		} else {
			partialPublicKeys[r.prevId(id)] = m.P
		}
		if ppk, ok := partialPublicKeys[r.nextId(id)]; ok {
			if !ppk.Equal(m.N) {
				return nil, errs.NewFailed("inconsistent commit message")
			}
		} else {
			partialPublicKeys[r.nextId(id)] = m.N
		}
	}

	group := edwards25519.NewPrimeSubGroup()
	field := edwards25519.NewScalarField()
	f0 := group.Zero()
	f1 := group.Zero()
	for id := range r.party.quorum.Iter() {
		ppk, ok := partialPublicKeys[id]
		if !ok {
			return nil, errs.NewFailed("missing partial public key")
		}
		f0 = f0.Add(ppk)
		f1Inv, err := field.FromUint64(uint64(id)).TryInv()
		if err != nil {
			return nil, errs.WrapFailed(err, "cannot create partial public key")
		}
		f1 = f1.Sub(ppk.ScalarMul(f1Inv))
	}

	poly := polynomials.NewPolynomialModule(edwards25519.NewPrimeSubGroup())
	fv := poly.New(f0, f1)
	return fv, nil
}

func (r *Runner) prevIdx(idx int) int {
	return (idx + 2) % 3
}

func (r *Runner) prevId(id sharing.ID) sharing.ID {
	idx := slices.Index(r.quorumList, id)
	return r.quorumList[r.prevIdx(idx)]
}

func (r *Runner) nextIdx(idx int) int {
	return (idx + 1) % 3
}

func (r *Runner) nextId(id sharing.ID) sharing.ID {
	idx := slices.Index(r.quorumList, id)
	return r.quorumList[r.nextIdx(idx)]
}
