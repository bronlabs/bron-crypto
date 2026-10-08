package signing_softspoken

import (
	"maps"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/dkls23"
	"github.com/bronlabs/bron-crypto/pkg/network"
)

// PreSign executes the message-independent part of protocol round 5 and returns
// a presignature that can later be finalised with a message via
// [dkls23.PreSignature.Finalise].
func (c *Cosigner[P, B, S]) PreSign(r4b network.RoundMessages[*Round4Broadcast[P, B, S], *Cosigner[P, B, S]], r4u network.RoundMessages[*Round4P2P[P, B, S], *Cosigner[P, B, S]]) (*dkls23.PreSignature[P, B, S], error) {
	if c.state.round != 5 {
		return nil, dkls23.ErrFailed.WithMessage("round 5 is not the expected round")
	}
	if err := network.ValidateIncomingMessages(c, c.ctx.OtherPartiesOrdered(), r4b); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid broadcast input")
	}
	if err := network.ValidateIncomingMessages(c, c.ctx.OtherPartiesOrdered(), r4u); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid p2p input")
	}

	psi := c.suite.ScalarField().Zero()
	cudu := c.suite.ScalarField().Zero()
	cvdv := c.suite.ScalarField().Zero()
	for id := range c.ctx.OtherPartiesOrdered() {
		bIn, _ := r4b.Get(id)
		uIn, _ := r4u.Get(id)
		if err := c.state.ck.Open(c.state.bigRCommitment[id], bIn.BigR.ToCompressed(), bIn.BigRWitness); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid commitment")
		}
		c.state.bigR[id] = bIn.BigR

		d, err := c.bobMul[id].Round3(uIn.MulR2)
		if err != nil {
			if errs.Is(err, base.ErrAbort) {
				return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot run Bob mul round3")
			}
			return nil, errs.Wrap(err).WithMessage("cannot run Bob mul round3")
		}
		if !c.state.bigR[id].ScalarMul(c.state.chi[id]).Sub(uIn.GammaU).Equal(c.suite.Curve().ScalarBaseMul(d[0])) {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("consistency check failed")
		}
		if !bIn.Pk.ScalarMul(c.state.chi[id]).Sub(uIn.GammaV).Equal(c.suite.Curve().ScalarBaseMul(d[1])) {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("consistency check failed")
		}
		c.state.pk[id] = bIn.Pk

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
	rxi, err := bigR.AffineX()
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert to affine x")
	}
	rx, err := c.suite.ScalarField().FromWideBytes(rxi.Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert to scalar")
	}

	preSignature, err := dkls23.NewPreSignature(bigR, rx, u, v, c.state.phi)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create presignature")
	}
	c.state.round++
	return preSignature, nil
}
