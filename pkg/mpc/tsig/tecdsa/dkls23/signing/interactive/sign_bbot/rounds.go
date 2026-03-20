package sign_bbot

import (
	"maps"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	hash_comm "github.com/bronlabs/bron-crypto/pkg/commitments/hash"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/session"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/unanimity"
	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

// Round1 executes protocol round 1.
func (c *Cosigner[P, B, S]) Round1() (r1bOut *Round1Broadcast[P, B, S], r1uOut network.RoundMessages[*Round1P2P[P, B, S], *Cosigner[P, B, S]], err error) {
	if c.state.round != 1 {
		return nil, nil, ErrFailed.WithMessage("invalid round")
	}

	var ck [hash_comm.KeySize]byte
	ckBytes, err := c.ctx.Transcript().ExtractBytes(ckLabel, uint(len(ck)))
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
	c.state.bigR[c.shard.Share().ID()] = c.suite.Curve().ScalarBaseMul(c.state.r)
	c.state.bigRCommitment = make(map[sharing.ID]hash_comm.Commitment)
	committer, err := c.state.ck.Committer()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create committer")
	}
	c.state.bigRCommitment[c.shard.Share().ID()], c.state.bigRWitness, err = committer.Commit(c.state.bigR[c.shard.Share().ID()].ToCompressed(), c.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot commit to r")
	}

	c.state.phi, err = c.suite.ScalarField().Random(c.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample phi")
	}

	r1b := &Round1Broadcast[P, B, S]{
		BigRCommitment: c.state.bigRCommitment[c.shard.Share().ID()],
	}
	r1u := hashmap.NewComparable[sharing.ID, *Round1P2P[P, B, S]]()
	for id := range c.ctx.OtherPartiesOrdered() {
		uOut := new(Round1P2P[P, B, S])
		var err error
		uOut.MulR1, err = c.state.aliceMul[id].Round1()
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run Alice mul round1")
		}
		r1u.Put(id, uOut)
	}

	c.state.round++
	return r1b, r1u.Freeze(), nil
}

// Round2 executes protocol round 2.
func (c *Cosigner[P, B, S]) Round2(r1b network.RoundMessages[*Round1Broadcast[P, B, S], *Cosigner[P, B, S]], r1u network.RoundMessages[*Round1P2P[P, B, S], *Cosigner[P, B, S]]) (r2bOut *Round2Broadcast[P, B, S], r2uOut network.RoundMessages[*Round2P2P[P, B, S], *Cosigner[P, B, S]], err error) {
	if c.state.round != 2 {
		return nil, nil, ErrFailed.WithMessage("invalid round")
	}
	if err := network.ValidateIncomingMessages(c, c.ctx.OtherPartiesOrdered(), r1b); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid broadcast input")
	}
	if err := network.ValidateIncomingMessages(c, c.ctx.OtherPartiesOrdered(), r1u); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid p2p input")
	}

	c.state.chi = make(map[sharing.ID]S)
	r2b := &Round2Broadcast[P, B, S]{
		BigR:        c.state.bigR[c.shard.Share().ID()],
		BigRWitness: c.state.bigRWitness,
	}
	r2u := hashmap.NewComparable[sharing.ID, *Round2P2P[P, B, S]]()
	for id := range c.ctx.OtherPartiesOrdered() {
		bIn, _ := r1b.Get(id)
		uIn, _ := r1u.Get(id)
		uOut := new(Round2P2P[P, B, S])

		c.state.bigRCommitment[id] = bIn.BigRCommitment
		uOut.MulR2, c.state.chi[id], err = c.state.bobMul[id].Round2(uIn.MulR1)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run bob mul round2")
		}
		r2u.Put(id, uOut)
	}

	c.state.round++
	return r2b, r2u.Freeze(), nil
}

// Round3 executes protocol round 3.
func (c *Cosigner[P, B, S]) Round3(r2b network.RoundMessages[*Round2Broadcast[P, B, S], *Cosigner[P, B, S]], r2u network.RoundMessages[*Round2P2P[P, B, S], *Cosigner[P, B, S]]) (r3bOut *Round3Broadcast[P, B, S], r3uOut network.RoundMessages[*Round3P2P[P, B, S], *Cosigner[P, B, S]], err error) {
	if c.state.round != 3 {
		return nil, nil, ErrFailed.WithMessage("invalid round")
	}
	if err := network.ValidateIncomingMessages(c, c.ctx.OtherPartiesOrdered(), r2b); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid broadcast input")
	}
	if err := network.ValidateIncomingMessages(c, c.ctx.OtherPartiesOrdered(), r2u); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid p2p input")
	}

	zeta, err := session.SampleZeroShare(c.ctx, c.suite.ScalarField())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot run zero setup round3")
	}
	quorum, err := unanimity.NewUnanimityAccessStructure(c.ctx.Quorum())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create minimal qualified access structure")
	}
	sk, err := c.shard.Share().ToAdditive(quorum)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("to additive share failed")
	}

	c.state.sk = sk.Add(zeta).Value()
	c.state.pk = make(map[sharing.ID]P)
	c.state.pk[c.shard.Share().ID()] = c.suite.Curve().ScalarBaseMul(c.state.sk)
	c.state.c = make(map[sharing.ID][]S)
	verifier, err := c.state.ck.Verifier()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create verifier")
	}

	r3b := &Round3Broadcast[P, B, S]{Pk: c.state.pk[c.shard.Share().ID()]}
	r3u := hashmap.NewComparable[sharing.ID, *Round3P2P[P, B, S]]()
	for id := range c.ctx.OtherPartiesOrdered() {
		bIn, _ := r2b.Get(id)
		uIn, _ := r2u.Get(id)
		uOut := new(Round3P2P[P, B, S])

		if err := verifier.Verify(c.state.bigRCommitment[id], bIn.BigR.ToCompressed(), bIn.BigRWitness); err != nil {
			return nil, nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid commitment")
		}
		c.state.bigR[id] = bIn.BigR
		uOut.MulR3, c.state.c[id], err = c.state.aliceMul[id].Round3(uIn.MulR2, []S{c.state.r, c.state.sk})
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot run alice mul round3")
		}
		uOut.GammaU = c.suite.Curve().ScalarBaseMul(c.state.c[id][0])
		uOut.GammaV = c.suite.Curve().ScalarBaseMul(c.state.c[id][1])
		uOut.Psi = c.state.phi.Sub(c.state.chi[id])
		r3u.Put(id, uOut)
	}

	c.state.round++
	return r3b, r3u.Freeze(), nil
}

// Round4 executes protocol round 4.
func (c *Cosigner[P, B, S]) Round4(r3b network.RoundMessages[*Round3Broadcast[P, B, S], *Cosigner[P, B, S]], r3u network.RoundMessages[*Round3P2P[P, B, S], *Cosigner[P, B, S]], message []byte) (partialSignature *dkls23.PartialSignature[P, B, S], err error) {
	if c.state.round != 4 {
		return nil, ErrFailed.WithMessage("invalid round")
	}
	if err := network.ValidateIncomingMessages(c, c.ctx.OtherPartiesOrdered(), r3b); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid broadcast input")
	}
	if err := network.ValidateIncomingMessages(c, c.ctx.OtherPartiesOrdered(), r3u); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid p2p input")
	}

	psi := c.suite.ScalarField().Zero()
	cudu := c.suite.ScalarField().Zero()
	cvdv := c.suite.ScalarField().Zero()
	for id := range c.ctx.OtherPartiesOrdered() {
		bIn, _ := r3b.Get(id)
		uIn, _ := r3u.Get(id)

		d, err := c.state.bobMul[id].Round4(uIn.MulR3)
		if err != nil {
			if errs.Is(err, base.ErrAbort) {
				return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot run Bob mul round4")
			}
			return nil, errs.Wrap(err).WithMessage("cannot run Bob mul round4")
		}
		c.state.pk[id] = bIn.Pk

		if !c.state.bigR[id].ScalarMul(c.state.chi[id]).Sub(uIn.GammaU).Equal(c.suite.Curve().ScalarBaseMul(d[0])) {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("consistency check failed")
		}
		if !bIn.Pk.ScalarMul(c.state.chi[id]).Sub(uIn.GammaV).Equal(c.suite.Curve().ScalarBaseMul(d[1])) {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("consistency check failed")
		}

		psi = psi.Add(uIn.Psi)
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
		return nil, errs.Wrap(err).WithMessage("cannot convert digest to scalar")
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
	return partialSignature, nil
}
