package sign

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/threshold/rvole/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/scheme/zero/przs"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tecdsa/dkls23"
	"github.com/bronlabs/errs-go/errs"
)

// Round1 executes protocol round 1.
func (c *Cosigner[P, B, S]) Round1() (network.OutgoingUnicasts[*Round1P2P[P, B, S]], error) {
	r1u := hashmap.NewComparable[sharing.ID, *Round1P2P[P, B, S]]()
	for id, u := range outgoingP2PMessages(c, r1u) {
		var err error
		u.OtR1, err = c.baseOtSenders[id].Round1()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 1 of VSOT party")
		}
	}

	c.state.round++
	return r1u.Freeze(), nil
}

// Round2 executes protocol round 2.
func (c *Cosigner[P, B, S]) Round2(r1u network.RoundMessages[*Round1P2P[P, B, S]]) (network.OutgoingUnicasts[*Round2P2P[P, B, S]], error) {
	incomingP2PMessages, err := validateIncomingP2PMessages(c, 2, r1u)
	if err != nil {
		return nil, ErrFailed.WithMessage("invalid input or round mismatch")
	}

	otR1 := hashmap.NewComparable[sharing.ID, *ecbbot.Round1P2P[P, S]]()
	for id, m := range incomingP2PMessages {
		otR1.Put(id, m.OtR1)
	}

	globalOtTape := c.tape.Clone()
	globalOtTape.AppendDomainSeparator(otRandomizerLabel)
	r2u := hashmap.NewComparable[sharing.ID, *Round2P2P[P, B, S]]()
	for id, u := range outgoingP2PMessages(c, r2u) {
		otR1u, ok := otR1.Get(id)
		if !ok {
			return nil, ErrFailed.WithMessage("cannot run round 2 of VSOT setup party")
		}
		choices := make([]byte, (softspoken.Kappa+7)/8)
		_, err = io.ReadFull(c.prng, choices)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot sample choices")
		}
		var seed *ecbbot.ReceiverOutput[S]
		u.OtR2, seed, err = c.baseOtReceivers[id].Round2(otR1u, choices)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 2 of VSOT party")
		}

		otTape := globalOtTape.Clone()
		otTape.AppendBytes(otRandomizerSender, binary.LittleEndian.AppendUint64(nil, uint64(c.sharingID)))
		otTape.AppendBytes(otRandomizerReceiver, binary.LittleEndian.AppendUint64(nil, uint64(id)))
		otKey, err := otTape.ExtractBytes(otRandomizerKey, 32)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot extract OT randomizer key")
		}
		c.state.baseOtReceiverOutputs[id], err = seed.ToBitsOutput(baseOtMessageLength, otKey)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot convert seed to bits output")
		}
	}

	c.state.round++
	return r2u.Freeze(), nil
}

// Round3 executes protocol round 3.
func (c *Cosigner[P, B, S]) Round3(r2u network.RoundMessages[*Round2P2P[P, B, S]]) (*Round3Broadcast, network.OutgoingUnicasts[*Round3P2P], error) {
	incomingP2PMessages, err := validateIncomingP2PMessages(c, 3, r2u)
	if err != nil {
		return nil, nil, ErrFailed.WithMessage("invalid input or round mismatch")
	}

	otR2 := hashmap.NewComparable[sharing.ID, *ecbbot.Round2P2P[P, S]]()
	for id, m := range incomingP2PMessages {
		otR2.Put(id, m.OtR2)
	}
	globalOtTape := c.tape.Clone()
	globalOtTape.AppendDomainSeparator(otRandomizerLabel)

	var ck [hash_comm.KeySize]byte
	ckBytes, err := c.tape.ExtractBytes(ckLabel, uint(len(ck)))
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("failed to extract commitment key")
	}
	copy(ck[:], ckBytes)
	c.state.ck, err = hash_comm.NewScheme(ck)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create commitment scheme")
	}
	c.state.r, err = c.suite.ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample r")
	}
	c.state.bigR = make(map[sharing.ID]P)
	c.state.bigR[c.sharingID] = c.suite.Curve().ScalarBaseMul(c.state.r)
	c.state.bigRCommitment = make(map[sharing.ID]hash_comm.Commitment)
	committer, err := c.state.ck.Committer()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create committer")
	}
	c.state.bigRCommitment[c.sharingID], c.state.bigRWitness, err = committer.Commit(c.state.bigR[c.sharingID].ToCompressed(), c.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot commit to r")
	}
	c.state.phi, err = c.suite.ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample phi")
	}
	c.state.chi = make(map[sharing.ID]S)

	bOut := &Round3Broadcast{
		BigRCommitment: c.state.bigRCommitment[c.sharingID],
	}

	mulSuite, err := rvole_softspoken.NewSuite(2, c.suite.Curve(), sha256.New)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create mul suite")
	}
	uOut := hashmap.NewComparable[sharing.ID, *Round3P2P]()
	for id, message := range outgoingP2PMessages(c, uOut) {
		otR2u, ok := otR2.Get(id)
		if !ok {
			return nil, nil, ErrFailed.WithMessage("missing OT message")
		}
		seed, err := c.baseOtSenders[id].Round3(otR2u)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run round 3 of VSOT party")
		}

		otTape := globalOtTape.Clone()
		otTape.AppendBytes(otRandomizerSender, binary.LittleEndian.AppendUint64(nil, uint64(id)))
		otTape.AppendBytes(otRandomizerReceiver, binary.LittleEndian.AppendUint64(nil, uint64(c.sharingID)))
		otKey, err := otTape.ExtractBytes(otRandomizerKey, base.CollisionResistanceBytesCeil)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot extract OT randomizer key")
		}
		c.state.baseOtSenderOutputs[id], err = seed.ToBitsOutput(baseOtMessageLength, otKey)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot convert seed to bits output")
		}
		aliceSeed, ok := c.state.baseOtReceiverOutputs[id]
		if !ok {
			return nil, nil, ErrFailed.WithMessage("couldn't find alice seed")
		}
		aliceTape := c.tape.Clone()
		aliceTape.AppendBytes(mulLabel, binary.LittleEndian.AppendUint64(nil, uint64(c.sharingID)), binary.LittleEndian.AppendUint64(nil, uint64(id)))
		c.aliceMul[id], err = rvole_softspoken.NewAlice(c.sessionID, mulSuite, aliceSeed, c.prng, aliceTape)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("couldn't initialise Alice")
		}

		bobSeed, ok := c.state.baseOtSenderOutputs[id]
		if !ok {
			return nil, nil, ErrFailed.WithMessage("couldn't find bob seed")
		}
		bobTape := c.tape.Clone()
		bobTape.AppendBytes(mulLabel, binary.LittleEndian.AppendUint64(nil, uint64(id)), binary.LittleEndian.AppendUint64(nil, uint64(c.sharingID)))
		c.bobMul[id], err = rvole_softspoken.NewBob(c.sessionID, mulSuite, bobSeed, c.prng, bobTape)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("couldn't initialise Bob")
		}

		message.MulR1, c.state.chi[id], err = c.bobMul[id].Round1()
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run Bob mul round1")
		}
	}

	c.state.round++
	return bOut, uOut.Freeze(), nil
}

// Round4 executes protocol round 4.
func (c *Cosigner[P, B, S]) Round4(r3b network.RoundMessages[*Round3Broadcast], r3u network.RoundMessages[*Round3P2P]) (r4b *Round4Broadcast[P, B, S], r4u network.OutgoingUnicasts[*Round4P2P[P, B, S]], err error) {
	incomingMessages, err := validateIncomingMessages(c, 4, r3b, r3u)
	if err != nil {
		return nil, nil, ErrFailed.WithMessage("invalid input or round mismatch")
	}

	mulR1 := make(map[sharing.ID]*rvole_softspoken.Round1P2P)
	for id, message := range incomingMessages {
		c.state.bigRCommitment[id] = message.broadcast.BigRCommitment
		mulR1[id] = message.p2p.MulR1
	}

	c.zeroSampler, err = przs.NewSampler(c.sharingID, c.quorum, c.zeroSeeds, c.suite.ScalarField())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot run zero setup round3")
	}
	zeta, err := c.zeroSampler.Sample()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot run zero setup round3")
	}

	quorum, err := accessstructures.NewUnanimityAccessStructure(c.quorum)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create minimal qualified access structure")
	}
	sk, err := c.shard.Share().ToAdditive(quorum)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("to additive share failed")
	}
	c.state.sk = sk.Value().Add(zeta)
	c.state.pk = make(map[sharing.ID]P)
	c.state.pk[c.sharingID] = c.suite.Curve().ScalarBaseMul(c.state.sk)
	c.state.c = make(map[sharing.ID][]S)

	bOut := &Round4Broadcast[P, B, S]{
		BigR:        c.state.bigR[c.sharingID],
		BigRWitness: c.state.bigRWitness,
		Pk:          c.state.pk[c.sharingID],
	}
	uOut := hashmap.NewComparable[sharing.ID, *Round4P2P[P, B, S]]()
	for id, message := range outgoingP2PMessages(c, uOut) {
		message.MulR2, c.state.c[id], err = c.aliceMul[id].Round2(mulR1[id], []S{c.state.r, c.state.sk})
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run alice mul round2")
		}
		message.GammaU = c.suite.Curve().ScalarBaseMul(c.state.c[id][0])
		message.GammaV = c.suite.Curve().ScalarBaseMul(c.state.c[id][1])
		message.Psi = c.state.phi.Sub(c.state.chi[id])
	}

	c.state.round++
	return bOut, uOut.Freeze(), nil
}

// Round5 executes protocol round 5.
func (c *Cosigner[P, B, S]) Round5(r4b network.RoundMessages[*Round4Broadcast[P, B, S]], r4u network.RoundMessages[*Round4P2P[P, B, S]], message []byte) (partialSignature *dkls23.PartialSignature[P, B, S], err error) {
	incomingMessages, err := validateIncomingMessages(c, 5, r4b, r4u)
	if err != nil {
		return nil, ErrFailed.WithMessage("invalid input or round mismatch")
	}

	psi := c.suite.ScalarField().Zero()
	cudu := c.suite.ScalarField().Zero()
	cvdv := c.suite.ScalarField().Zero()
	verifier, err := c.state.ck.Verifier()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create verifier")
	}
	for id, message := range incomingMessages {
		if err := verifier.Verify(c.state.bigRCommitment[id], message.broadcast.BigR.ToCompressed(), message.broadcast.BigRWitness); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid commitment")
		}
		c.state.bigR[id] = message.broadcast.BigR

		d, err := c.bobMul[id].Round3(message.p2p.MulR2)
		if err != nil {
			if errs.Is(err, base.ErrAbort) {
				return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot run Bob mul round3")
			}
			return nil, errs.Wrap(err).WithMessage("cannot run Bob mul round3")
		}
		if !c.state.bigR[id].ScalarMul(c.state.chi[id]).Sub(message.p2p.GammaU).Equal(c.suite.Curve().ScalarBaseMul(d[0])) {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("consistency check failed")
		}
		if !message.broadcast.Pk.ScalarMul(c.state.chi[id]).Sub(message.p2p.GammaV).Equal(c.suite.Curve().ScalarBaseMul(d[1])) {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("consistency check failed")
		}
		c.state.pk[id] = message.broadcast.Pk

		psi = psi.Add(message.p2p.Psi)
		cudu = cudu.Add(c.state.c[id][0].Add(d[0]))
		cvdv = cvdv.Add(c.state.c[id][1].Add(d[1]))
	}

	bigR := sliceutils.Fold(func(x, y P) P { return x.Add(y) }, c.suite.Curve().OpIdentity(), slices.Collect(maps.Values(c.state.bigR))...)
	pk := sliceutils.Fold(func(x, y P) P { return x.Add(y) }, c.suite.Curve().OpIdentity(), slices.Collect(maps.Values(c.state.pk))...)
	if !pk.Equal(c.shard.PublicKey().Value()) {
		return nil, base.ErrAbort.WithMessage("consistency check failed")
	}

	u := c.state.r.Mul(c.state.phi.Add(psi)).Add(cudu)
	v := c.state.sk.Mul(c.state.phi.Add(psi)).Add(cvdv)
	digest, err := hashing.Hash(c.suite.HashFunc(), message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot hash message")
	}
	m, err := ecdsa.DigestToScalar(c.suite.ScalarField(), digest)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute message scalar")
	}
	rxi, err := bigR.AffineX()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert to affine x")
	}
	rx, err := c.suite.ScalarField().FromWideBytes(rxi.Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert to scalar")
	}
	w := m.Mul(c.state.phi).Add(rx.Mul(v))

	partialSignature, err = dkls23.NewPartialSignature(bigR, u, w)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create partial signature")
	}

	c.state.round++
	return partialSignature, nil
}
