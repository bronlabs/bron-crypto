package signing_softspoken

import (
	"crypto/sha256"
	"encoding/binary"
	"io"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	rvole_softspoken "github.com/bronlabs/bron-crypto/pkg/mpc/rvole/softspoken"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/przs"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/softspoken"
)

// Round1 executes protocol round 1.
func (c *Cosigner[P, B, S]) Round1() (network.OutgoingUnicasts[*Round1P2P[P, B, S], *Cosigner[P, B, S]], error) {
	if c.state.round != 1 {
		return nil, dkls23.ErrValidationFailed.WithMessage("invalid round")
	}
	r1u := hashmap.NewComparable[sharing.ID, *Round1P2P[P, B, S]]()
	for id := range c.ctx.OtherPartiesOrdered() {
		uOut := new(Round1P2P[P, B, S])
		var err error
		uOut.OtR1, err = c.baseOtSenders[id].Round1()
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 1 of VSOT party")
		}
		r1u.Put(id, uOut)
	}

	c.state.round++
	return r1u.Freeze(), nil
}

// Round2 executes protocol round 2.
func (c *Cosigner[P, B, S]) Round2(r1u network.RoundMessages[*Round1P2P[P, B, S], *Cosigner[P, B, S]]) (network.OutgoingUnicasts[*Round2P2P[P, B, S], *Cosigner[P, B, S]], error) {
	if c.state.round != 2 {
		return nil, dkls23.ErrFailed.WithMessage("round 2 is not the expected round")
	}
	if err := network.ValidateIncomingMessages(c, c.ctx.OtherPartiesOrdered(), r1u); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid input")
	}

	globalOtTape := c.ctx.Transcript().Clone()
	globalOtTape.AppendDomainSeparator(otRandomizerLabel)
	r2u := hashmap.NewComparable[sharing.ID, *Round2P2P[P, B, S]]()
	for id := range c.ctx.OtherPartiesOrdered() {
		uOut := new(Round2P2P[P, B, S])
		uIn, _ := r1u.Get(id)
		choices := make([]byte, (softspoken.Kappa+7)/8)
		_, err := io.ReadFull(c.prng, choices)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot sample choices")
		}
		var seed *ecbbot.ReceiverOutput[S]
		uOut.OtR2, seed, err = c.baseOtReceivers[id].Round2(uIn.OtR1, choices)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot run round 2 of VSOT party")
		}

		otTape := globalOtTape.Clone()
		otTape.AppendBytes(otRandomizerSender, binary.LittleEndian.AppendUint64(nil, uint64(c.ctx.HolderID())))
		otTape.AppendBytes(otRandomizerReceiver, binary.LittleEndian.AppendUint64(nil, uint64(id)))
		otKey, err := otTape.ExtractBytes(otRandomizerKey, 32)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot extract OT randomizer key")
		}
		c.state.baseOtReceiverOutputs[id], err = seed.ToBitsOutput(baseOtMessageLength, otKey)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot convert seed to bits output")
		}
		r2u.Put(id, uOut)
	}

	c.state.round++
	return r2u.Freeze(), nil
}

// Round3 executes protocol round 3.
func (c *Cosigner[P, B, S]) Round3(r2u network.RoundMessages[*Round2P2P[P, B, S], *Cosigner[P, B, S]]) (*Round3Broadcast[P, B, S], network.OutgoingUnicasts[*Round3P2P[P, B, S], *Cosigner[P, B, S]], error) {
	if c.state.round != 3 {
		return nil, nil, dkls23.ErrFailed.WithMessage("round 3 is not the expected round")
	}
	if err := network.ValidateIncomingMessages(c, c.ctx.OtherPartiesOrdered(), r2u); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid input")
	}

	globalOtTape := c.ctx.Transcript().Clone()
	globalOtTape.AppendDomainSeparator(otRandomizerLabel)

	var err error
	c.state.ck, err = hashcom.ExtractCommitmentKey(c.ctx.Transcript(), ckLabel)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create commitment scheme")
	}
	c.state.r, err = c.suite.ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample r")
	}
	c.state.bigR = make(map[sharing.ID]P)
	c.state.bigR[c.ctx.HolderID()] = c.suite.Curve().ScalarBaseMul(c.state.r)
	c.state.bigRCommitment = make(map[sharing.ID]hashcom.Commitment)
	c.state.bigRCommitment[c.ctx.HolderID()], c.state.bigRWitness, err = commitments.Commit(c.state.ck, c.state.bigR[c.ctx.HolderID()].ToCompressed(), c.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot commit to r")
	}
	c.state.phi, err = c.suite.ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample phi")
	}
	c.state.chi = make(map[sharing.ID]S)

	bOut := &Round3Broadcast[P, B, S]{
		BigRCommitment: c.state.bigRCommitment[c.ctx.HolderID()],
	}

	mulSuite, err := rvole_softspoken.NewSuite(2, c.suite.Curve(), sha256.New)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create mul suite")
	}
	r3u := hashmap.NewComparable[sharing.ID, *Round3P2P[P, B, S]]()
	for id := range c.ctx.OtherPartiesOrdered() {
		uOut := new(Round3P2P[P, B, S])
		uIn, _ := r2u.Get(id)

		seed, err := c.baseOtSenders[id].Round3(uIn.OtR2)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run round 3 of VSOT party")
		}

		otTape := globalOtTape.Clone()
		otTape.AppendBytes(otRandomizerSender, binary.LittleEndian.AppendUint64(nil, uint64(id)))
		otTape.AppendBytes(otRandomizerReceiver, binary.LittleEndian.AppendUint64(nil, uint64(c.ctx.HolderID())))
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
			return nil, nil, dkls23.ErrFailed.WithMessage("couldn't find alice seed")
		}
		aliceCtx, err := c.ctx.SubContext(hashset.NewComparable(c.ctx.HolderID(), id).Freeze())
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create subcontext")
		}
		aliceCtx.Transcript().AppendBytes(mulLabel, binary.LittleEndian.AppendUint64(nil, uint64(c.ctx.HolderID())), binary.LittleEndian.AppendUint64(nil, uint64(id)))
		c.aliceMul[id], err = rvole_softspoken.NewAlice(aliceCtx, mulSuite, aliceSeed, c.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("couldn't initialise Alice")
		}

		bobSeed, ok := c.state.baseOtSenderOutputs[id]
		if !ok {
			return nil, nil, dkls23.ErrFailed.WithMessage("couldn't find bob seed")
		}
		bobCtx, err := c.ctx.SubContext(hashset.NewComparable(c.ctx.HolderID(), id).Freeze())
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create subcontext")
		}
		bobCtx.Transcript().AppendBytes(mulLabel, binary.LittleEndian.AppendUint64(nil, uint64(id)), binary.LittleEndian.AppendUint64(nil, uint64(c.ctx.HolderID())))
		c.bobMul[id], err = rvole_softspoken.NewBob(bobCtx, mulSuite, bobSeed, c.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("couldn't initialise Bob")
		}

		uOut.MulR1, c.state.chi[id], err = c.bobMul[id].Round1()
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run Bob mul round1")
		}
		r3u.Put(id, uOut)
	}

	c.state.round++
	return bOut, r3u.Freeze(), nil
}

// Round4 executes protocol round 4.
func (c *Cosigner[P, B, S]) Round4(r3b network.RoundMessages[*Round3Broadcast[P, B, S], *Cosigner[P, B, S]], r3u network.RoundMessages[*Round3P2P[P, B, S], *Cosigner[P, B, S]]) (*Round4Broadcast[P, B, S], network.OutgoingUnicasts[*Round4P2P[P, B, S], *Cosigner[P, B, S]], error) {
	if c.state.round != 4 {
		return nil, nil, dkls23.ErrFailed.WithMessage("round 4 is not the expected round")
	}
	if err := network.ValidateIncomingMessages(c, c.ctx.OtherPartiesOrdered(), r3b); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid broadcast input")
	}
	if err := network.ValidateIncomingMessages(c, c.ctx.OtherPartiesOrdered(), r3u); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid p2p input")
	}

	field := algebra.StructureMustBeAs[algebra.PrimeField[S]](c.shard.Share().Value()[0].Structure())
	zeta, err := przs.SampleZeroShare(c.ctx, field)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot run zero setup round3")
	}

	quorum, err := unanimity.NewUnanimityAccessStructure(c.ctx.Quorum())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create minimal qualified access structure")
	}
	sk, err := c.sharingScheme.ConvertShareToAdditive(c.shard.Share(), quorum)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("to additive share failed")
	}
	c.state.sk = sk.Add(zeta).Value()
	c.state.pk = make(map[sharing.ID]P)
	c.state.pk[c.ctx.HolderID()] = c.suite.Curve().ScalarBaseMul(c.state.sk)
	c.state.c = make(map[sharing.ID][]S)

	r4b := &Round4Broadcast[P, B, S]{
		BigR:        c.state.bigR[c.ctx.HolderID()],
		BigRWitness: c.state.bigRWitness,
		Pk:          c.state.pk[c.ctx.HolderID()],
	}
	r4u := hashmap.NewComparable[sharing.ID, *Round4P2P[P, B, S]]()
	for id := range c.ctx.OtherPartiesOrdered() {
		uOut := new(Round4P2P[P, B, S])
		uIn, _ := r3u.Get(id)
		bIn, _ := r3b.Get(id)
		c.state.bigRCommitment[id] = bIn.BigRCommitment

		uOut.MulR2, c.state.c[id], err = c.aliceMul[id].Round2(uIn.MulR1, []S{c.state.r, c.state.sk})
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run alice mul round2")
		}
		uOut.GammaU = c.suite.Curve().ScalarBaseMul(c.state.c[id][0])
		uOut.GammaV = c.suite.Curve().ScalarBaseMul(c.state.c[id][1])
		uOut.Psi = c.state.phi.Sub(c.state.chi[id])
		r4u.Put(id, uOut)
	}

	c.state.round++
	return r4b, r4u.Freeze(), nil
}

// Round5 executes protocol round 5.
func (c *Cosigner[P, B, S]) Round5(r4b network.RoundMessages[*Round4Broadcast[P, B, S], *Cosigner[P, B, S]], r4u network.RoundMessages[*Round4P2P[P, B, S], *Cosigner[P, B, S]], message []byte) (*dkls23.PartialSignature[P, B, S], error) {
	preSignature, err := c.PreSign(r4b, r4u)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot presign")
	}
	partialSignature, err := preSignature.Finalise(c.suite, message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot finalise")
	}
	return partialSignature, nil
}
