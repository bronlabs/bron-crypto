package dkg

import (
	"crypto/subtle"
	"io"
	"maps"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/maputils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/hashcom"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/dh/dhc"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/blummod"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/fac"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/batch_schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/prm"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir/zkmodule"
	"github.com/bronlabs/errs-go/errs"
	"golang.org/x/sync/errgroup"
)

func (p *Participant[P, B, S]) Round1() (*Round1Broadcast[P, B, S], error) {
	if p.round != 1 {
		return nil, cggmp21.ErrRound.WithMessage("actual=%d, expected=%d", p.round, 1)
	}
	eg := errgroup.Group{}
	// step 1(a)
	eg.Go(func() error {
		var err error
		p.state.paillierSecretKey, err = paillier.SampleBlumSecretKey(base.IFCKeyLength, p.prng)
		if err != nil {
			return errs.Wrap(err).WithMessage("cannot sample Paillier secret key")
		}
		return nil
	})
	// step 1(b)
	eg.Go(func() error {
		var err error
		p.state.ringPedersenSecretKey, err = intcom.SampleTrapdoorKey(base.IFCKeyLength, p.prng)
		if err != nil {
			return errs.Wrap(err).WithMessage("cannot sample ring-Pedersen trapdoor key")
		}
		prmProver, err := p.state.prmfs.NewProver(p.state.proverCtx)
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
	if err := eg.Wait(); err != nil {
		return nil, errs.Wrap(err).WithMessage("round 1 failed")
	}
	// step 1(d)
	zero, err := additive.NewSecret(p.curve.ScalarField().Zero())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create additive secret for zero")
	}
	do, err := p.state.additiveSharing.Deal(zero, p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create additive sharing of zero")
	}
	for id, share := range do.Shares().Iter() {
		p.state.sharesOfZero[id] = share
		p.state.Xi[id] = p.curve.ScalarBaseMul(share.Value())
	}

	// step 1(c)
	for id := range p.ctx.Quorum().Iter() {
		p.state.dhPrivateKeys[id], err = dhc.SampleExtendedPrivateKey(p.curve.ScalarField(), p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot sample DH private key")
		}
		p.state.Yi[id], err = dhc.PublicKeyOf(p.curve, p.state.dhPrivateKeys[id])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot compute DH public key")
		}
	}

	// step 1(e)
	p.state.schnorrWitness = batch_schnorr.NewWitness(sliceutils.Map(maputils.SortedValues(p.state.sharesOfZero), func(s *additive.Share[S]) S { return s.Value() })...)
	p.state.schnorrStatement = batch_schnorr.NewStatement(p.curve.Generator(), maputils.SortedValues(p.state.Xi)...)
	p.state.Ai, p.state.tau, err = zkmodule.Commit(p.state.schnorrScheme, p.state.schnorrStatement, p.state.schnorrWitness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create commitment for shares of zero")
	}

	// step 1(f)
	if _, err := io.ReadFull(p.prng, p.state.rid); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot generate random identifier")
	}

	r1b := &Round1Broadcast[P, B, S]{}
	p.state.comMsg = &CommitmentMessage[P, B, S]{
		SessionID:                 p.ctx.SessionID(),
		SharingID:                 p.ctx.HolderID(),
		XVector:                   p.state.Xi,
		YVector:                   p.state.Yi,
		PaillierPublicKey:         p.state.paillierSecretKey.Public(),
		RingPedersenCommitmentKey: p.state.ringPedersenSecretKey.Export(),
		Psi:                       p.state.psi_i,
		Rid:                       p.state.rid,
	}
	r1b.V, p.state.u_i, err = commitments.Commit(p.state.commitmentKey, p.state.comMsg.Bytes(), p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create commitment for round 1 message")
	}
	p.round.IncrementBy(1)
	return r1b, nil
}

func (p *Participant[P, B, S]) Round2(r1b network.RoundMessages[*Round1Broadcast[P, B, S], *Participant[P, B, S]]) (*Round2Broadcast[P, B, S], error) {
	if p.round != 2 {
		return nil, cggmp21.ErrRound.WithMessage("actual=%d, expected=%d", p.round, 2)
	}
	if err := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r1b); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid incoming messages")
	}
	for id := range p.ctx.OtherPartiesOrdered() {
		b, _ := r1b.Get(id)
		p.state.receivedVjs[id] = b.V
	}
	// step 2
	r2b := &Round2Broadcast[P, B, S]{
		Message: p.state.comMsg,
		U:       p.state.u_i,
	}
	p.round.IncrementBy(1)
	return r2b, nil
}

func (p *Participant[P, B, S]) Round3(r2b network.RoundMessages[*Round2Broadcast[P, B, S], *Participant[P, B, S]]) (*Round3Broadcast[P, B, S], network.OutgoingUnicasts[*Round3P2P[P, B, S], *Participant[P, B, S]], error) {
	if p.round != 3 {
		return nil, nil, cggmp21.ErrRound.WithMessage("actual=%d, expected=%d", p.round, 3)
	}
	if errB := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r2b); errB != nil {
		return nil, nil, errs.Wrap(errB).WithMessage("invalid incoming broadcast messages")
	}
	r3b := &Round3Broadcast[P, B, S]{}
	r3u := hashmap.NewComparable[sharing.ID, *Round3P2P[P, B, S]]()
	// step 3.1
	for id := range p.ctx.OtherPartiesOrdered() {
		b, _ := r2b.Get(id)
		p.state.receivedComMsg[id] = b.Message
		// step 3.1(a)
		if b.Message.PaillierPublicKey.Group().N().AnnouncedLen() != base.IFCKeyLength {
			return nil, nil, cggmp21.ErrValidationFailed.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid modulus length")
		}
		if b.Message.RingPedersenCommitmentKey.Group().Modulus().AnnouncedLen() != base.IFCKeyLength {
			return nil, nil, cggmp21.ErrValidationFailed.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid ring-Pedersen modulus length")
		}
		if !algebrautils.Sum(p.curve.OpIdentity(), slices.Collect(maps.Values(b.Message.XVector))...).IsOpIdentity() {
			return nil, nil, cggmp21.ErrValidationFailed.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("X vector is not a dealing of zero")
		}
		prmVerifier, err := p.state.prmfs.NewVerifier(p.state.verifierCtxs[id])
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create PRM verifier")
		}
		prmStatement, err := prm.NewStatement(b.Message.RingPedersenCommitmentKey)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create PRM statement")
		}
		if err := prmVerifier.Verify(prmStatement, b.Message.Psi); err != nil {
			return nil, nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid PRM proof")
		}
		// step 3.1(b)
		if p.state.commitmentKey.Open(p.state.receivedVjs[id], b.Message.Bytes(), b.U) != nil {
			return nil, nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid commitment opening")
		}
		// step 3.2
		subtle.XORBytes(p.state.rid, p.state.rid, b.Message.Rid)
	}

	// "rid" is a shared aux for the proofs, so we append to the transcript once to be shared.
	p.state.proverCtx.Transcript().AppendBytes(ridLabel, p.state.rid)

	// step 3.2(a)
	blummodProver, err := p.state.blummodfs.NewProver(p.state.proverCtx)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create BlumMod prover")
	}
	blummodStatement, err := blummod.NewStatement(p.state.paillierSecretKey.Public())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create BlumMod statement")
	}
	blummodWitness, err := blummod.NewWitness(p.state.paillierSecretKey)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create BlumMod witness")
	}
	psiIPrime, err := blummodProver.Prove(blummodStatement, blummodWitness)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot generate BlumMod proof")
	}

	// step 3.2(b, c)
	facStatement, err := fac.NewStatement(p.state.paillierSecretKey.Public())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create FAC statement")
	}
	facWitness, err := fac.NewWitness(p.state.paillierSecretKey)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create FAC witness")
	}
	for id := range p.ctx.OtherPartiesOrdered() {
		// step 3.2(b)
		facInteractiveProtocol, err := fac.NewProtocol(p.state.receivedComMsg[id].RingPedersenCommitmentKey, p.Ell(), p.Epislon(), p.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create FAC interactive protocol")
		}
		p.state.facfs[id], err = fiatshamir.NewCompiler(facInteractiveProtocol)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create Fiat-Shamir compiler for FAC protocol")
		}
		facProver, err := p.state.facfs[id].NewProver(p.state.proverCtx)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create FAC prover")
		}
		psiJI, err := facProver.Prove(facStatement, facWitness)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot generate FAC proof")
		}

		// step 3.2(c)
		rhoIJDigest, err := hashing.HashIndexLengthPrefixed(hashcom.HashFunc, p.state.rid, p.SharingID().Bytes(), p.state.Yi[id].Value().ToCompressed())
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot compute rhoIJ digest")
		}
		rhoIJ, err := p.curve.ScalarField().Hash(rhoIJDigest)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot compute rhoIJ")
		}
		CJI := p.state.sharesOfZero[id].Value().Add(rhoIJ)

		r3u.Put(id, &Round3P2P[P, B, S]{
			PsiJI:     psiJI,
			CJI:       CJI,
			PsiIPrime: psiIPrime, // PsiIPrime is the same for all parties, but, following the paper, we include it in each P2P message to lower the bandwitdh of broadcast messages.
		})
	}

	// step 3.2(d) is done once, because we are using batch schnorr.
	r3b.PsiHat, err = zkmodule.Prove(p.state.proverCtx, p.state.schnorrScheme, p.state.schnorrStatement, p.state.schnorrWitness, p.state.Ai, p.state.tau)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot generate batch Schnorr proof")
	}

	return r3b, r3u.Freeze(), nil
}
