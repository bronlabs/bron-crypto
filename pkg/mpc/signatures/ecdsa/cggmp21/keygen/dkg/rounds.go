package dkg

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/maputils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/dh/dhc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/prm"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir/zkmodule"
	"github.com/bronlabs/errs-go/errs"
	"golang.org/x/sync/errgroup"
)

func (p *Participant[P, B, S]) Round1() (*Round1Broadcast[P, B, S], error) {
	if p.round != 1 {
		return nil, cggmp21.ErrRound.WithMessage("actual=%d, expected=%d", p.round, 1)
	}
	eg := errgroup.Group{}
	var r1b *Round1Broadcast[P, B, S]
	// step 6.1
	eg.Go(func() error {
		var err error
		r1b.Canetti, err = p.canettiParticipant.Round1()
		if err != nil {
			return errs.Wrap(err).WithMessage("canetti round 1 failed")
		}
		return nil
	})
	// step 7.1(a)
	eg.Go(func() error {
		var err error
		p.state.paillierSecretKey, err = paillier.SampleBlumSecretKey(base.IFCKeyLength, p.PRNG())
		if err != nil {
			return errs.Wrap(err).WithMessage("cannot sample Paillier secret key")
		}
		return nil
	})
	// step 7.1(b)
	eg.Go(func() error {
		var err error
		p.state.ringPedersenSecretKey, err = intcom.SampleTrapdoorKey(base.IFCKeyLength, p.PRNG())
		if err != nil {
			return errs.Wrap(err).WithMessage("cannot sample ring-Pedersen trapdoor key")
		}
		prmProver, err := p.state.prm.NewProver(p.Ctx())
		if err != nil {
			return errs.Wrap(err).WithMessage("cannot create PRM prover")
		}
		prmStatement, err := prm.NewStatement(p.state.ringPedersenSecretKey.Export())
		if err != nil {
			return errs.Wrap(err).WithMessage("cannot create PRM statement")
		}
		prmWitness, err := prm.NewWitness(p.state.ringPedersenSecretKey)
		if err != nil {
			return errs.Wrap(err).WithMessage("cannot create PRM witness")
		}
		p.state.psi_i, err = prmProver.Prove(prmStatement, prmWitness)
		if err != nil {
			return errs.Wrap(err).WithMessage("cannot generate PRM proof")
		}
		return nil
	})
	// step 7.1(c, d, e)
	eg.Go(func() error {
		var err error
		// step 7.1(c)
		for id := range p.Ctx().Quorum().Iter() {
			p.state.dhPrivateKeys[id], err = dhc.SampleExtendedPrivateKey(p.curve.ScalarField(), p.PRNG())
			if err != nil {
				return errs.Wrap(err).WithMessage("cannot sample DH private key")
			}
			p.state.Yi[id], err = dhc.PublicKeyOf(p.curve, p.state.dhPrivateKeys[id])
			if err != nil {
				return errs.Wrap(err).WithMessage("cannot compute DH public key")
			}
		}
		// step 7.1(d)
		zero, err := additive.NewSecret(p.curve.ScalarField().Zero())
		if err != nil {
			return errs.Wrap(err).WithMessage("cannot create additive secret for zero")
		}
		do, err := p.state.additiveSharing.Deal(zero, p.PRNG())
		if err != nil {
			return errs.Wrap(err).WithMessage("cannot create additive sharing of zero")
		}
		for id, share := range do.Shares().Iter() {
			p.state.sharesOfZero[id] = share
			p.state.Xi[id] = p.curve.ScalarBaseMul(share.Value())
		}

		// step 7.1(e)
		schnorrWitness := batch_schnorr.NewWitness(sliceutils.Map(maputils.SortedValues(p.state.sharesOfZero), func(s *additive.Share[S]) S {
			return s.Value()
		})...)
		schnorrStatement := batch_schnorr.NewStatement(p.curve.Generator(), maputils.SortedValues(p.state.Xi)...)
		p.state.Ai, p.state.tau, err = zkmodule.Commit(p.state.schnorrScheme, schnorrStatement, schnorrWitness)
		if err != nil {
			return errs.Wrap(err).WithMessage("cannot create commitment for shares of zero")
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		return nil, errs.Wrap(err).WithMessage("round 1 failed")
	}
	// step 7.1(f)
	if _, err := io.ReadFull(p.PRNG(), p.state.rid_i); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot generate random identifier")
	}

	var err error
	msg := &CommitmentMessage[P, B, S]{
		SessionID: p.Ctx().SessionID(),
		SharingID: p.Ctx().HolderID(),
		X:         p.state.Xi,
		Y:         p.state.Yi,
		N:         p.state.paillierSecretKey.Group().Modulus(),
		NHat:      p.state.ringPedersenSecretKey.Group().Modulus(),
		s:         p.state.ringPedersenSecretKey.S(),
		t:         p.state.ringPedersenSecretKey.T(),
		psi:       p.state.psi_i,
		rid:       p.state.rid_i,
	}
	r1b.V, p.state.u_i, err = commitments.Commit(p.state.commitmentKey, msg.Bytes(), p.PRNG())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create commitment for round 1 message")
	}
	p.round.IncrementBy(1)
	return r1b, nil
}
