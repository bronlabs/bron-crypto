package signing

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/hjky"
	"github.com/bronlabs/bron-crypto/pkg/network"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/affg"
	"github.com/bronlabs/bron-crypto/pkg/proofs/cggmp21/encelg"
	"github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/elgamal/elcomop"
	"github.com/bronlabs/bron-crypto/pkg/proofs/elgamal/elog"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func (s *Signer[P, B, S]) Round1() (*Round1Broadcast[P, B, S], network.OutgoingUnicasts[*Round1P2P[P, B, S], *Signer[P, B, S]], error) {
	if s.state.round != 1 {
		return nil, nil, ErrInvalidRound.WithMessage("actual=%d expected=%d", s.state.round, 1)
	}

	s.ctx.Transcript().AppendBytes(publicKeyValueLabel, s.shard.PublicKey().Value().Bytes())
	s.ctx.Transcript().AppendBytes(ridLabel, s.shard.RefreshID())

	zeroR1b, zeroR1u, err := s.zeroParty.Round1()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot run HJKY round 1")
	}

	k, err := algebrautils.RandomNonIdentity(s.params.ScalarField(), s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample k")
	}
	auxInfo := s.shard.AuxInfo()
	bigK, rho, err := paillierEncryptScalar(auxInfo.PaillierSecretKey(), k, s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot encrypt k")
	}
	gamma, err := algebrautils.RandomNonIdentity(s.params.ScalarField(), s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample gamma")
	}
	bigG, nu, err := paillierEncryptScalar(auxInfo.PaillierSecretKey(), gamma, s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot encrypt gamma")
	}
	elgamalSecretKey, err := elgamal.SampleSecretKey(s.params.CurveGroup(), s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample ElGamal secret key")
	}
	bigY := elgamalSecretKey.Public()
	kElgamalPlaintext, err := elgamal.NewPlaintext(s.params.CurveGroup().ScalarBaseMul(k))
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create ElGamal plaintext for k")
	}
	bigA, a, err := encryption.Encrypt(kElgamalPlaintext, bigY, s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot encrypt ElGamal plaintext for k")
	}
	gammaElgamalPlaintext, err := elgamal.NewPlaintext(s.params.CurveGroup().ScalarBaseMul(gamma))
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create ElGamal plaintext for gamma")
	}
	bigB, b, err := encryption.Encrypt(gammaElgamalPlaintext, bigY, s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot encrypt ElGamal plaintext for gamma")
	}

	psi0 := make(map[sharing.ID]compiler.NIZKPoKProof)
	psi1 := make(map[sharing.ID]compiler.NIZKPoKProof)
	for j := range s.ctx.OtherPartiesOrdered() {
		encElgSigma, err := encelg.NewProtocol(s.shard.AuxInfo().RingPedersenPublicKeys()[j], s.params.L(), s.params.Epsilon(), s.params.CurveGroup(), s.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create enc-elg protocol")
		}
		encElg, err := fiatshamir.NewCompiler(encElgSigma)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create NI enc-elg protocol")
		}

		proverCtx, err := s.ctx.SubContext(hashset.NewComparable(s.ctx.HolderID(), j).Freeze())
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create subcontext")
		}
		proverCtx.Transcript().AppendBytes(proverID, s.shard.Share().ID().Bytes())
		prover, err := encElg.NewProver(proverCtx)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create prover")
		}

		k0, err := num.Z().FromUnsignedNumeric(k)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot convert scalar to integer")
		}
		witness0, err := encelg.NewWitness(k0, rho, elgamalSecretKey, a)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create enc-elg witness")
		}
		statement0, err := encelg.NewStatement(auxInfo.PaillierSecretKey().Public(), bigK, bigY, bigA)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create enc-elg statement")
		}
		proof0, err := prover.Prove(statement0, witness0)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create enc-elg proof")
		}

		gamma1, err := num.Z().FromUnsignedNumeric(gamma)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot convert scalar to integer")
		}
		witness1, err := encelg.NewWitness(gamma1, nu, elgamalSecretKey, b)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create enc-elg witness")
		}
		statement1, err := encelg.NewStatement(auxInfo.PaillierSecretKey().Public(), bigG, bigY, bigB)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create enc-elg statement")
		}
		proof1, err := prover.Prove(statement1, witness1)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create enc-elg proof")
		}

		psi0[j] = proof0
		psi1[j] = proof1
	}

	s.state.k = k
	s.state.gamma = gamma
	s.state.rho = rho
	s.state.nu = nu
	s.state.bigYJ = make(map[sharing.ID]*elgamal.PublicKey[P, S])
	s.state.bigYJ[s.ctx.HolderID()] = bigY
	s.state.a = a
	s.state.b = b
	s.state.bigAJ = make(map[sharing.ID]*elgamal.Ciphertext[P, S])
	s.state.bigAJ[s.ctx.HolderID()] = bigA
	s.state.bigBJ = make(map[sharing.ID]*elgamal.Ciphertext[P, S])
	s.state.bigBJ[s.ctx.HolderID()] = bigB
	r1b := &Round1Broadcast[P, B, S]{
		ZeroR1: zeroR1b,
		BigK:   bigK,
		BigG:   bigG,
		BigY:   bigY,
		BigA:   bigA,
		BigB:   bigB,
	}

	r1u := hashmap.NewComparable[sharing.ID, *Round1P2P[P, B, S]]()
	for id := range s.ctx.OtherPartiesOrdered() {
		u, ok := zeroR1u.Get(id)
		if !ok {
			return nil, nil, ErrFailed.WithMessage("missing zero-party round 1 unicast for %d", id)
		}
		r1u.Put(id, &Round1P2P[P, B, S]{
			ZeroR1: u,
			Psi0:   psi0[id],
			Psi1:   psi1[id],
		})
	}

	s.state.round1Broadcasts = map[sharing.ID]*Round1Broadcast[P, B, S]{
		s.ctx.HolderID(): r1b,
	}
	s.state.round++
	return r1b, r1u.Freeze(), nil
}

func (s *Signer[P, B, S]) Round2(
	r1b network.RoundMessages[*Round1Broadcast[P, B, S], *Signer[P, B, S]],
	r1u network.RoundMessages[*Round1P2P[P, B, S], *Signer[P, B, S]],
) (*Round2Broadcast[P, B, S], network.OutgoingUnicasts[*Round2P2P[P, B, S], *Signer[P, B, S]], error) {
	if s.state.round != 2 {
		return nil, nil, ErrInvalidRound.WithMessage("actual=%d expected=%d", s.state.round, 2)
	}
	if errB := network.ValidateIncomingMessages(s, s.ctx.OtherPartiesOrdered(), r1b); errB != nil {
		return nil, nil, errs.Wrap(errB).WithMessage("invalid round 1 broadcast messages")
	}
	if errU := network.ValidateIncomingMessages(s, s.ctx.OtherPartiesOrdered(), r1u); errU != nil {
		return nil, nil, errs.Wrap(errU).WithMessage("invalid round 1 P2P messages")
	}

	zeroR1b := hashmap.NewComparable[sharing.ID, *hjky.Round1Broadcast[P, S]]()
	zeroR1u := hashmap.NewComparable[sharing.ID, *hjky.Round1P2P[P, S]]()
	encElgSigma, err := encelg.NewProtocol(s.shard.AuxInfo().RingPedersenSecretKey().Export(), s.params.L(), s.params.Epsilon(), s.params.CurveGroup(), s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create enc-elg protocol")
	}
	encElg, err := fiatshamir.NewCompiler(encElgSigma)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create NI enc-elg protocol")
	}
	for j := range s.ctx.OtherPartiesOrdered() {
		b, _ := r1b.Get(j)
		u, _ := r1u.Get(j)
		zeroR1b.Put(j, b.ZeroR1)
		zeroR1u.Put(j, u.ZeroR1)

		verifierCtx, err := s.ctx.SubContext(hashset.NewComparable(j, s.ctx.HolderID()).Freeze())
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create subcontext")
		}
		verifierCtx.Transcript().AppendBytes(proverID, j.Bytes())
		verifier, err := encElg.NewVerifier(verifierCtx)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create verifier")
		}

		statement0, err := encelg.NewStatement(s.shard.AuxInfo().PaillierPublicKeys()[j], b.BigK, b.BigY, b.BigA)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create enc-elg statement")
		}
		if err := verifier.Verify(statement0, u.Psi0); err != nil {
			return nil, nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, j).WithMessage("cannot verify enc-elg statement")
		}

		statement1, err := encelg.NewStatement(s.shard.AuxInfo().PaillierPublicKeys()[j], b.BigG, b.BigY, b.BigB)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create enc-elg statement")
		}
		if err := verifier.Verify(statement1, u.Psi1); err != nil {
			return nil, nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, j).WithMessage("cannot verify enc-elg statement")
		}
		s.state.bigAJ[j] = b.BigA
		s.state.bigBJ[j] = b.BigB
	}

	round1Broadcasts, err := collectAndAppendBroadcastMessages(s, round1BroadcastTranscriptLabel, s.state.round1Broadcasts[s.ctx.HolderID()], r1b)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot append round 1 broadcasts to transcript")
	}

	shiftShare, zeroVerificationVector, err := s.zeroParty.Round2(zeroR1b.Freeze(), zeroR1u.Freeze())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot compute zero-party round 2")
	}
	partialPublicKeys, zeroShift, err := s.computeEffectivePartialPublicKeys(shiftShare, zeroVerificationVector)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot compute effective partial public keys")
	}
	bigX, ok := partialPublicKeys[s.ctx.HolderID()]
	if !ok {
		return nil, nil, ErrFailed.WithMessage("missing local effective partial public key")
	}
	x := s.state.x.Add(zeroShift)
	bigGamma := s.params.CurveGroup().ScalarBaseMul(s.state.gamma)

	elogCk, err := indcpacom.NewCommitmentKey(s.state.bigYJ[s.ctx.HolderID()])
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create commitment key")
	}
	elogSigma, err := elog.NewProtocol(s.params.CurveGroup(), elogCk, s.params.CurveGroup().Generator(), s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create elog protocol")
	}
	elogNI, err := fiatshamir.NewCompiler(elogSigma)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create NI elog protocol")
	}
	gammaElgamalPlaintext, err := elgamal.NewPlaintext(s.params.CurveGroup().ScalarBaseMul(s.state.gamma))
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create elgamal plaintext")
	}
	gammaElgamalMessage, err := indcpacom.NewMessage(gammaElgamalPlaintext)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create elgamal message")
	}
	bElgamalWitness, err := indcpacom.NewWitness(s.state.b)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create witness")
	}
	elcomopWitness, err := elcomop.NewWitness(gammaElgamalMessage, bElgamalWitness)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create witness")
	}
	schWitness := schnorr.NewWitness(s.state.gamma)
	elogWitness, err := elog.NewWitness(elcomopWitness, schWitness)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create witness")
	}
	bElgamalCommitment, err := indcpacom.NewCommitment(s.state.bigBJ[s.ctx.HolderID()])
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create commitment")
	}
	elcomopStatement, err := elcomop.NewStatement(bElgamalCommitment)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create statement")
	}
	schStatement := schnorr.NewStatement(bigGamma)
	elogStatement, err := elog.NewStatement(elcomopStatement, schStatement)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create statement")
	}
	elogProverCtx := s.ctx.Clone()
	elogProverCtx.Transcript().AppendBytes(proverID, s.ctx.HolderID().Bytes())
	elogProver, err := elogNI.NewProver(elogProverCtx)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create prover")
	}
	psi, err := elogProver.Prove(elogStatement, elogWitness)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create elog proof")
	}

	r2b := &Round2Broadcast[P, B, S]{
		BigGamma: bigGamma,
		Psi:      psi,
	}

	bigYJ := make(map[sharing.ID]*elgamal.PublicKey[P, S])
	for id, bigY := range s.state.bigYJ {
		bigYJ[id] = bigY
	}
	betaJ := make(map[sharing.ID]*num.Int)
	betaHatJ := make(map[sharing.ID]*num.Int)
	r2u := hashmap.NewComparable[sharing.ID, *Round2P2P[P, B, S]]()
	for j := range s.ctx.OtherPartiesOrdered() {
		b, _ := r1b.Get(j)
		bigYJ[j] = b.BigY
		bigKj := b.BigK

		paillierPublicKey, ok := s.shard.AuxInfo().PaillierPublicKey(j)
		if !ok {
			return nil, nil, cggmp21.ErrValidationFailed.WithMessage("missing Paillier public key for %d", j)
		}
		beta, err := sampleMask(s.params.LPrime(), s.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot sample beta for %d", j)
		}
		betaJ[j] = beta
		bigDJ, bigFJ, r, ss, err := paillierMaskedProduct(paillierPublicKey, bigKj, s.state.gamma, beta, s.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, j).WithMessage("cannot compute masked gamma product for %d", j)
		}
		betaHat, err := sampleMask(s.params.LPrime(), s.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot sample beta-hat for %d", j)
		}
		betaHatJ[j] = betaHat
		bigDHatJ, bigFHatJ, rHat, sHat, err := paillierMaskedProduct(paillierPublicKey, bigKj, x, betaHat, s.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, j).WithMessage("cannot compute masked x product for %d", j)
		}

		affgSigma, err := affg.NewProtocol(s.shard.AuxInfo().RingPedersenPublicKeys()[j], s.params.L(), s.params.LPrime(), s.params.Epsilon(), s.params.CurveGroup(), s.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create affg protocol")
		}
		affgNI, err := fiatshamir.NewCompiler(affgSigma)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create NI affg compiler")
		}

		affgProverCtx, err := s.ctx.SubContext(hashset.NewComparable(s.ctx.HolderID(), j).Freeze())
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create subcontext")
		}
		affgProverCtx.Transcript().AppendBytes(proverID, s.ctx.HolderID().Bytes())
		affgProver, err := affgNI.NewProver(affgProverCtx)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create affg prover")
		}

		gammaInt, err := num.Z().FromUnsignedNumeric(s.state.gamma)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot convert gamma to integer")
		}
		betaAffine := beta.Neg()
		betaPlaintext, err := paillier.NewPlaintextSymmetric(betaAffine, paillierPublicKey.PlaintextGroup().Modulus())
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create beta plaintext")
		}
		// note: the paper’s signing invocation and Figure 25’s relation have a sign mismatch so we inverse (F, s)
		sInv, err := paillierPublicKey.NonceOpInv(ss)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot invert beta nonce")
		}
		bigFInv, err := paillierPublicKey.CiphertextOpInv(bigFJ)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot invert BigF")
		}
		affgWitness, err := affg.NewWitness(gammaInt, betaPlaintext, r, sInv)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create affg witness")
		}
		affgStatement, err := affg.NewStatement(paillierPublicKey, paillierPublicKey, bigKj, bigDJ, bigFInv, bigGamma)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create affg statement")
		}
		affgPsi, err := affgProver.Prove(affgStatement, affgWitness)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create affg proof")
		}

		xInt, err := num.Z().FromUnsignedNumeric(x)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot convert x to integer")
		}
		betaHatAffine := betaHat.Neg()
		betaHatPlaintext, err := paillier.NewPlaintextSymmetric(betaHatAffine, paillierPublicKey.PlaintextGroup().Modulus())
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create beta-hat plaintext")
		}
		// note: the paper’s signing invocation and Figure 25’s relation have a sign mismatch so we inverse (F^, s^)
		sHatInv, err := paillierPublicKey.NonceOpInv(sHat)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot invert beta-hat nonce")
		}
		bigFHatInv, err := paillierPublicKey.CiphertextOpInv(bigFHatJ)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot invert BigFHat")
		}
		affgHatWitness, err := affg.NewWitness(xInt, betaHatPlaintext, rHat, sHatInv)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create affg-hat witness")
		}
		affgHatStatement, err := affg.NewStatement(paillierPublicKey, paillierPublicKey, bigKj, bigDHatJ, bigFHatInv, bigX)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create affg-hat statement")
		}
		affgPsiHat, err := affgProver.Prove(affgHatStatement, affgHatWitness)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot create affg-hat proof")
		}

		r2u.Put(j, &Round2P2P[P, B, S]{
			BigD:    bigDJ,
			BigF:    bigFJ,
			BigDHat: bigDHatJ,
			BigFHat: bigFHatJ,
			Psi:     affgPsi,
			PsiHat:  affgPsiHat,
		})
	}

	s.state.bigYJ = bigYJ
	s.state.betaJ = betaJ
	s.state.betaHatJ = betaHatJ
	s.state.partialPublicKeys = partialPublicKeys
	s.state.x = x
	s.state.round1Broadcasts = round1Broadcasts
	s.state.round2Broadcasts = map[sharing.ID]*Round2Broadcast[P, B, S]{
		s.ctx.HolderID(): r2b,
	}

	s.state.round++
	return r2b, r2u.Freeze(), nil
}

func (s *Signer[P, B, S]) Round3(
	r2b network.RoundMessages[*Round2Broadcast[P, B, S], *Signer[P, B, S]],
	r2u network.RoundMessages[*Round2P2P[P, B, S], *Signer[P, B, S]],
) (*Round3Broadcast[P, B, S], error) {
	if s.state.round != 3 {
		return nil, ErrInvalidRound.WithMessage("actual=%d expected=%d", s.state.round, 3)
	}
	if err := network.ValidateIncomingMessages(s, s.ctx.OtherPartiesOrdered(), r2b); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid round 2 broadcast messages")
	}
	if err := network.ValidateIncomingMessages(s, s.ctx.OtherPartiesOrdered(), r2u); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid round 2 P2P messages")
	}

	bigGamma := s.params.CurveGroup().ScalarBaseMul(s.state.gamma)
	delta := s.state.gamma.Mul(s.state.k)
	chi := s.state.k.Mul(s.state.x)
	for j := range s.ctx.OtherPartiesOrdered() {
		b, _ := r2b.Get(j)
		u, _ := r2u.Get(j)

		elogCk, err := indcpacom.NewCommitmentKey(s.state.bigYJ[j])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create commitment key")
		}
		elogSigma, err := elog.NewProtocol(s.params.CurveGroup(), elogCk, s.params.CurveGroup().Generator(), s.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create elog protocol")
		}
		elogNI, err := fiatshamir.NewCompiler(elogSigma)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create NI elog protocol")
		}
		bElgamalCommitment, err := indcpacom.NewCommitment(s.state.bigBJ[j])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create commitment")
		}
		elcomopStatement, err := elcomop.NewStatement(bElgamalCommitment)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create statement")
		}
		schStatement := schnorr.NewStatement(b.BigGamma)
		elogStatement, err := elog.NewStatement(elcomopStatement, schStatement)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create statement")
		}
		elogVerifierCtx := s.ctx.Clone()
		elogVerifierCtx.Transcript().AppendBytes(proverID, j.Bytes())
		elogVerifier, err := elogNI.NewVerifier(elogVerifierCtx)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create verifier")
		}
		if err := elogVerifier.Verify(elogStatement, b.Psi); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, j)
		}
		bigGamma = bigGamma.Add(b.BigGamma)

		affgSigma, err := affg.NewProtocol(s.shard.AuxInfo().RingPedersenSecretKey().Export(), s.params.L(), s.params.LPrime(), s.params.Epsilon(), s.params.CurveGroup(), s.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create affg protocol")
		}
		affgNI, err := fiatshamir.NewCompiler(affgSigma)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create NI affg compiler")
		}
		affgVerifierCtx, err := s.ctx.SubContext(hashset.NewComparable(j, s.ctx.HolderID()).Freeze())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create subcontext")
		}
		affgVerifierCtx.Transcript().AppendBytes(proverID, j.Bytes())
		affgVerifier, err := affgNI.NewVerifier(affgVerifierCtx)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create affg verifier")
		}

		localPaillierPublicKey := s.shard.AuxInfo().PaillierSecretKey().Public()
		localBigK := s.state.round1Broadcasts[s.ctx.HolderID()].BigK
		bigFInv, err := localPaillierPublicKey.CiphertextOpInv(u.BigF)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot invert BigF")
		}
		affgStatement, err := affg.NewStatement(localPaillierPublicKey, localPaillierPublicKey, localBigK, u.BigD, bigFInv, b.BigGamma)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create affg statement")
		}
		if err := affgVerifier.Verify(affgStatement, u.Psi); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, j).WithMessage("cannot verify affg statement")
		}
		bigFHatInv, err := localPaillierPublicKey.CiphertextOpInv(u.BigFHat)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot invert BigFHat")
		}
		bigXJ, ok := s.state.partialPublicKeys[j]
		if !ok {
			return nil, ErrFailed.WithMessage("missing effective partial public key for %d", j)
		}
		affgHatStatement, err := affg.NewStatement(localPaillierPublicKey, localPaillierPublicKey, localBigK, u.BigDHat, bigFHatInv, bigXJ)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create affg-hat statement")
		}
		if err := affgVerifier.Verify(affgHatStatement, u.PsiHat); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, j).WithMessage("cannot verify affg-hat statement")
		}

		alphaJ, err := s.shard.AuxInfo().PaillierSecretKey().Decrypt(u.BigD)
		if err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, j).WithMessage("cannot decrypt BigD from %d", j)
		}
		alphaScalar, err := paillierPlaintextToScalar(alphaJ, s.params.ScalarField())
		if err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, j).WithMessage("cannot convert BigD plaintext from %d", j)
		}
		betaScalar, err := intToScalar(s.state.betaJ[j], s.params.ScalarField())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot convert local beta for %d", j)
		}
		delta = delta.Add(alphaScalar).Add(betaScalar)

		alphaHatJ, err := s.shard.AuxInfo().PaillierSecretKey().Decrypt(u.BigDHat)
		if err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, j).WithMessage("cannot decrypt BigDHat from %d", j)
		}
		alphaHatScalar, err := paillierPlaintextToScalar(alphaHatJ, s.params.ScalarField())
		if err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, j).WithMessage("cannot convert BigDHat plaintext from %d", j)
		}
		betaHatScalar, err := intToScalar(s.state.betaHatJ[j], s.params.ScalarField())
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot convert local beta-hat for %d", j)
		}
		chi = chi.Add(alphaHatScalar).Add(betaHatScalar)
	}

	round2Broadcasts, err := collectAndAppendBroadcastMessages(s, round2BroadcastTranscriptLabel, s.state.round2Broadcasts[s.ctx.HolderID()], r2b)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot append round 2 broadcasts to transcript")
	}

	bigDelta := bigGamma.ScalarMul(s.state.k)
	bigS := bigGamma.ScalarMul(chi)

	elogCk, err := indcpacom.NewCommitmentKey(s.state.bigYJ[s.ctx.HolderID()])
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create commitment key")
	}
	elogSigma, err := elog.NewProtocol(s.params.CurveGroup(), elogCk, bigGamma, s.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create elog protocol")
	}
	elogNI, err := fiatshamir.NewCompiler(elogSigma)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create NI elog protocol")
	}
	kElgamalPlaintext, err := elgamal.NewPlaintext(s.params.CurveGroup().ScalarBaseMul(s.state.k))
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create ElGamal plaintext for k")
	}
	kElgamalMessage, err := indcpacom.NewMessage(kElgamalPlaintext)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create ElGamal message")
	}
	aElgamalWitness, err := indcpacom.NewWitness(s.state.a)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create ElGamal witness")
	}
	elcomopWitness, err := elcomop.NewWitness(kElgamalMessage, aElgamalWitness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create elcomop witness")
	}
	schWitness := schnorr.NewWitness(s.state.k)
	elogWitness, err := elog.NewWitness(elcomopWitness, schWitness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create elog witness")
	}
	aElgamalCommitment, err := indcpacom.NewCommitment(s.state.bigAJ[s.ctx.HolderID()])
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create ElGamal commitment")
	}
	elcomopStatement, err := elcomop.NewStatement(aElgamalCommitment)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create elcomop statement")
	}
	schStatement := schnorr.NewStatement(bigDelta)
	elogStatement, err := elog.NewStatement(elcomopStatement, schStatement)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create elog statement")
	}
	elogProverCtx := s.ctx.Clone()
	elogProverCtx.Transcript().AppendBytes(proverID, s.ctx.HolderID().Bytes())
	elogProver, err := elogNI.NewProver(elogProverCtx)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create elog prover")
	}
	psiPrime, err := elogProver.Prove(elogStatement, elogWitness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create elog proof")
	}

	s.state.delta = delta
	s.state.chi = chi
	s.state.bigGamma = bigGamma
	s.state.bigDeltaJ = make(map[sharing.ID]P)
	s.state.bigDeltaJ[s.ctx.HolderID()] = bigDelta
	s.state.bigSJ = make(map[sharing.ID]P)
	s.state.bigSJ[s.ctx.HolderID()] = bigS

	r3b := &Round3Broadcast[P, B, S]{
		Delta:    s.state.delta,
		BigS:     bigS,
		BigDelta: bigDelta,
		Psi:      psiPrime,
	}

	s.state.round2Broadcasts = round2Broadcasts
	s.state.round3Broadcasts = map[sharing.ID]*Round3Broadcast[P, B, S]{
		s.ctx.HolderID(): r3b,
	}
	s.state.round++
	return r3b, nil
}

func (s *Signer[P, B, S]) Round4(r3b network.RoundMessages[*Round3Broadcast[P, B, S], *Signer[P, B, S]], message []byte) (*cggmp21.PartialSignature[P, B, S], error) {
	if s.state.round != 4 {
		return nil, ErrInvalidRound.WithMessage("actual=%d expected=%d", s.state.round, 4)
	}
	if err := network.ValidateIncomingMessages(s, s.ctx.OtherPartiesOrdered(), r3b); err != nil {
		return nil, errs.Wrap(err).WithMessage("invalid round 3 broadcast messages")
	}

	delta := s.state.delta
	bigDeltaSum := s.state.bigDeltaJ[s.ctx.HolderID()]
	bigSSum := s.state.bigSJ[s.ctx.HolderID()]
	bigDeltaJ := make(map[sharing.ID]P)
	bigDeltaJ[s.ctx.HolderID()] = bigDeltaSum
	bigSJ := make(map[sharing.ID]P)
	bigSJ[s.ctx.HolderID()] = bigSSum
	for id := range s.ctx.OtherPartiesOrdered() {
		b, _ := r3b.Get(id)
		delta = delta.Add(b.Delta)
		bigDeltaSum = bigDeltaSum.Add(b.BigDelta)
		bigSSum = bigSSum.Add(b.BigS)
		bigDeltaJ[id] = b.BigDelta
		bigSJ[id] = b.BigS

		elogCk, err := indcpacom.NewCommitmentKey(s.state.bigYJ[id])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create commitment key")
		}
		elogSigma, err := elog.NewProtocol(s.params.CurveGroup(), elogCk, s.state.bigGamma, s.prng)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create elog protocol")
		}
		elogNI, err := fiatshamir.NewCompiler(elogSigma)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create NI elog protocol")
		}
		aElgamalCommitment, err := indcpacom.NewCommitment(s.state.bigAJ[id])
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create ElGamal commitment")
		}
		elcomopStatement, err := elcomop.NewStatement(aElgamalCommitment)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create elcomop statement")
		}
		schStatement := schnorr.NewStatement(b.BigDelta)
		elogStatement, err := elog.NewStatement(elcomopStatement, schStatement)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create elog statement")
		}
		elogVerifierCtx := s.ctx.Clone()
		elogVerifierCtx.Transcript().AppendBytes(proverID, id.Bytes())
		elogVerifier, err := elogNI.NewVerifier(elogVerifierCtx)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot create elog verifier")
		}
		if err := elogVerifier.Verify(elogStatement, b.Psi); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot verify elog statement")
		}
	}

	round3Broadcasts, err := collectAndAppendBroadcastMessages(s, round3BroadcastTranscriptLabel, s.state.round3Broadcasts[s.ctx.HolderID()], r3b)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot append round 3 broadcasts to transcript")
	}

	// verification
	if !s.params.CurveGroup().ScalarBaseMul(delta).Equal(bigDeltaSum) {
		return nil, base.ErrAbort.WithMessage("delta consistency check failed")
	}
	if !s.shard.PublicKeyValue().ScalarMul(delta).Equal(bigSSum) {
		return nil, base.ErrAbort.WithMessage("chi consistency check failed")
	}

	deltaInv, err := delta.TryInv()
	if err != nil {
		return nil, errs.Join(err, base.ErrAbort).WithMessage("cannot invert delta")
	}
	kTilde := s.state.k.Mul(deltaInv)
	chiTilde := s.state.chi.Mul(deltaInv)
	bigDeltaTildeJ := make(map[sharing.ID]P)
	bigSTildeJ := make(map[sharing.ID]P)
	for id := range s.ctx.AllPartiesOrdered() {
		bigDeltaTildeJ[id] = bigDeltaJ[id].ScalarMul(deltaInv)
		bigSTildeJ[id] = bigSJ[id].ScalarMul(deltaInv)
	}

	digest, err := hashing.Hash(s.ecdsaSuite.HashFunc(), message)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot hash signing message")
	}
	m, err := sigecdsa.DigestToScalar(s.params.ScalarField(), digest)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert digest to scalar")
	}
	rx, err := s.state.bigGamma.AffineX()
	if err != nil {
		return nil, errs.Join(err, base.ErrAbort).WithMessage("cannot get Gamma affine x-coordinate")
	}
	r, err := s.params.ScalarField().FromWideBytes(rx.Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert Gamma x-coordinate to scalar")
	}
	sigma := kTilde.Mul(m).Add(r.Mul(chiTilde))

	s.state.bigDeltaTildeJ = bigDeltaTildeJ
	s.state.bigSTildeJ = bigSTildeJ
	s.state.bigDeltaJ = bigDeltaJ
	s.state.bigSJ = bigSJ
	s.state.round3Broadcasts = round3Broadcasts
	s.state.m = m
	partialSignature := &cggmp21.PartialSignature[P, B, S]{
		Gamma: s.state.bigGamma,
		Sigma: sigma,
	}

	s.state.round++
	return partialSignature, nil
}

func (s *Signer[P, B, S]) Aggregate(partialSignatures map[sharing.ID]*cggmp21.PartialSignature[P, B, S]) (*sigecdsa.Signature[S], error) {
	if s.state.round != 5 {
		return nil, ErrInvalidRound.WithMessage("actual=%d expected=%d", s.state.round, 5)
	}

	rx, err := s.state.bigGamma.AffineX()
	if err != nil {
		return nil, errs.Join(err, base.ErrAbort).WithMessage("cannot get Gamma affine x-coordinate")
	}
	r, err := s.params.ScalarField().FromWideBytes(rx.Bytes())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert Gamma x-coordinate to scalar")
	}

	sig := s.ecdsaSuite.ScalarField().Zero()
	for id := range s.ctx.AllPartiesOrdered() {
		psig, ok := partialSignatures[id]
		if !ok {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("missing partial signature from %d", id)
		}
		if psig == nil {
			return nil, cggmp21.ErrNil.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("partial signature for %d", id)
		}
		if err := validatePoint(psig.Gamma, "Gamma", false); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid Gamma in partial signature from %d", id)
		}
		if err := validateScalar(psig.Sigma, "Sigma", true); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("invalid Sigma in partial signature from %d", id)
		}
		if !s.state.bigGamma.Equal(psig.Gamma) {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("Gamma mismatch in partial signature from %d", id)
		}
		if !s.state.bigGamma.ScalarMul(psig.Sigma).Equal(s.state.bigDeltaTildeJ[id].ScalarMul(s.state.m).Add(s.state.bigSTildeJ[id].ScalarMul(r))) {
			return nil, base.ErrAbort.WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("partial signature verification failed for %d", id)
		}
		sig = sig.Add(psig.Sigma)
	}
	v, err := sigecdsa.ComputeRecoveryID(s.state.bigGamma)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot compute recovery ID")
	}

	signature, err := sigecdsa.NewSignature(r, sig, &v)
	if err != nil {
		return nil, errs.Join(err, base.ErrAbort).WithMessage("cannot create ECDSA signature")
	}

	s.state.round = 0
	return signature, nil
}
