package dkg

import (
	"crypto/subtle"
	"io"

	"golang.org/x/sync/errgroup"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/blummod"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/fac"
	"github.com/bronlabs/bron-crypto/pkg/proofs/prm"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

// Round1 samples this party's Paillier secret key and ring-Pedersen trapdoor,
// proves the ring-Pedersen parameters well-formed (Π_prm), draws this party's
// rid share, and broadcasts a single hash commitment binding all of it. The
// commit-before-reveal structure prevents a rushing adversary from choosing its
// contribution after seeing the honest parties'. Must be called in round 1.
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
	// step 1(f)
	if _, err := io.ReadFull(p.prng, p.state.rid); err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot generate random identifier")
	}

	var err error
	r1b := &Round1Broadcast[P, B, S]{}
	p.state.comMsg = &CommitmentMessage[P, B, S]{
		SessionID:                 p.ctx.SessionID(),
		SharingID:                 p.ctx.HolderID(),
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

// Round2 records the other parties' round-1 commitments and broadcasts the
// opening of this party's own commitment — the CommitmentMessage and its
// hash-commitment witness. Must be called in round 2.
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

// Round3 opens and checks every party's commitment: it re-derives each digest
// and matches it against the round-1 V_j, checks the announced Paillier and
// ring-Pedersen modulus lengths, and verifies the Π_prm proofs. It then folds
// all rid shares into the shared rid = ⊕_j rid_j (bound into the proof contexts)
// and produces this party's proofs: one verifier-independent Paillier-Blum proof
// (Π_mod) and one no-small-factor proof (Π_fac) per other party, each computed
// against that verifier's ring-Pedersen setup. Any failed check aborts
// identifiably, tagging the culprit. Must be called in round 3.
func (p *Participant[P, B, S]) Round3(r2b network.RoundMessages[*Round2Broadcast[P, B, S], *Participant[P, B, S]]) (network.OutgoingUnicasts[*Round3P2P[P, B, S], *Participant[P, B, S]], error) {
	if p.round != 3 {
		return nil, cggmp21.ErrRound.WithMessage("actual=%d, expected=%d", p.round, 3)
	}
	if errB := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r2b); errB != nil {
		return nil, errs.Wrap(errB).WithMessage("invalid incoming broadcast messages")
	}
	r3u := hashmap.NewComparable[sharing.ID, *Round3P2P[P, B, S]]()
	// step 3.1
	for id := range p.ctx.OtherPartiesOrdered() {
		b, _ := r2b.Get(id)
		p.state.receivedPaillierPublicKeys[id] = b.Message.PaillierPublicKey
		p.state.receivedRingPedersenCommitmentKeys[id] = b.Message.RingPedersenCommitmentKey

		// step 3.1(a)
		if b.Message.PaillierPublicKey.Group().N().AnnouncedLen() != base.IFCKeyLength {
			return nil, cggmp21.ErrValidationFailed.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid modulus length")
		}
		if b.Message.RingPedersenCommitmentKey.Group().Modulus().AnnouncedLen() != base.IFCKeyLength {
			return nil, cggmp21.ErrValidationFailed.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid ring-Pedersen modulus length")
		}
		prmVerifier, err := p.state.prmfs.NewVerifier(p.state.verifierCtxs[id])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create PRM verifier")
		}
		prmStatement, err := prm.NewStatement(b.Message.RingPedersenCommitmentKey)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create PRM statement")
		}
		if err := prmVerifier.Verify(prmStatement, b.Message.Psi); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid PRM proof")
		}
		// step 3.1(b)
		if err := p.state.commitmentKey.Open(p.state.receivedVjs[id], b.Message.Bytes(), b.U); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid commitment opening")
		}
		// step 3.2
		subtle.XORBytes(p.state.rid, p.state.rid, b.Message.Rid)
	}

	// "rid" is a shared aux for the proofs, so we append to the transcript once to be shared.
	p.state.proverCtx.Transcript().AppendBytes(ridLabel, p.state.rid)

	// step 3.2(a)
	blummodProver, err := p.state.blummodfs.NewProver(p.state.proverCtx)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create BlumMod prover")
	}
	blummodStatement, err := blummod.NewStatement(p.state.paillierSecretKey.Public())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create BlumMod statement")
	}
	blummodWitness, err := blummod.NewWitness(p.state.paillierSecretKey)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create BlumMod witness")
	}
	psiIPrime, err := blummodProver.Prove(blummodStatement, blummodWitness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot generate BlumMod proof")
	}

	// step 3.2(b, c)
	facStatement, err := fac.NewStatement(p.state.paillierSecretKey.Public())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create FAC statement")
	}
	facWitness, err := fac.NewWitness(p.state.paillierSecretKey)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create FAC witness")
	}
	for id := range p.ctx.OtherPartiesOrdered() {
		// step 3.2(b)
		facInteractiveProtocol, err := fac.NewProtocol(p.state.receivedRingPedersenCommitmentKeys[id], p.Ell(), p.Epislon(), p.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create FAC interactive protocol")
		}
		facfs, err := fiatshamir.NewCompiler(facInteractiveProtocol)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create Fiat-Shamir compiler for FAC protocol")
		}
		// Each verifier checks this proof on its own independent context
		// (post-blummod), so prove on a fresh clone per verifier rather than the
		// shared proverCtx; otherwise every proof after the first is bound to a
		// transcript polluted by the preceding verifiers' FAC proofs.
		facProverCtx := p.state.proverCtx.Clone()
		facProver, err := facfs.NewProver(facProverCtx)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create FAC prover")
		}
		psiJI, err := facProver.Prove(facStatement, facWitness)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot generate FAC proof")
		}

		r3u.Put(id, &Round3P2P[P, B, S]{
			PsiJI:     psiJI,
			PsiIPrime: psiIPrime, // PsiIPrime is the same for all parties, but, following the paper, we include it in each P2P message to lower the bandwidth of broadcast messages.
		})
	}
	p.round.IncrementBy(1)
	return r3u.Freeze(), nil
}

// Round4 verifies every other party's Paillier-Blum (Π_mod) and no-small-factor
// (Π_fac) proofs against the shared rid — aborting identifiably on any failure —
// then assembles the auxiliary information (all parties' Paillier and
// ring-Pedersen public keys plus this party's own secret keys) and returns the
// input base shard augmented with it as a cggmp21.Shard. Must be called in
// round 4.
func (p *Participant[P, B, S]) Round4(r3u network.RoundMessages[*Round3P2P[P, B, S], *Participant[P, B, S]]) (*cggmp21.Shard[P, B, S], error) {
	if p.round != 4 {
		return nil, cggmp21.ErrRound.WithMessage("actual=%d, expected=%d", p.round, 4)
	}
	if errU := network.ValidateIncomingMessages(p, p.ctx.OtherPartiesOrdered(), r3u); errU != nil {
		return nil, errs.Wrap(errU).WithMessage("invalid incoming unicast messages")
	}

	facInteractiveProtocol, err := fac.NewProtocol(p.state.ringPedersenSecretKey.Export(), p.Ell(), p.Epislon(), p.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create FAC interactive protocol")
	}
	facfs, err := fiatshamir.NewCompiler(facInteractiveProtocol)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create Fiat-Shamir compiler for FAC protocol")
	}

	// step Output.1(b)
	for id := range p.ctx.OtherPartiesOrdered() {
		u, _ := r3u.Get(id)

		// rid is the common aux for the proofs, so we append to the transcript once to be shared.
		verifierCtx := p.state.verifierCtxs[id]
		verifierCtx.Transcript().AppendBytes(ridLabel, p.state.rid)

		// step Output.1(b).i
		blummodVerifier, err := p.state.blummodfs.NewVerifier(verifierCtx)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create BlumMod verifier")
		}
		blummodStatement, err := blummod.NewStatement(p.state.receivedPaillierPublicKeys[id])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create BlumMod statement")
		}
		if err := blummodVerifier.Verify(blummodStatement, u.PsiIPrime); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid BlumMod proof")
		}

		// step Output.1(b).ii
		facVerifier, err := facfs.NewVerifier(verifierCtx)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create FAC verifier")
		}
		facStatement, err := fac.NewStatement(p.state.receivedPaillierPublicKeys[id])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create FAC statement")
		}
		if err := facVerifier.Verify(facStatement, u.PsiJI); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid FAC proof")
		}
	}

	// The auxiliary info must cover every shareholder, including this party, so
	// include the local public keys alongside the ones received from others.
	p.state.receivedPaillierPublicKeys[p.ctx.HolderID()] = p.state.paillierSecretKey.Public()
	p.state.receivedRingPedersenCommitmentKeys[p.ctx.HolderID()] = p.state.ringPedersenSecretKey.Export()

	auxInfo, err := cggmp21.NewAuxInfo(p.state.paillierSecretKey, p.state.receivedPaillierPublicKeys, p.state.ringPedersenSecretKey, p.state.receivedRingPedersenCommitmentKeys)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create auxiliary info for shard generation")
	}
	shard, err := cggmp21.NewShard(p.baseShard, auxInfo)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create shard")
	}
	p.round.IncrementBy(1)
	return shard, nil
}
