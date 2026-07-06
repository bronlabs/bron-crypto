package signing

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/commitments/intcom"
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

// Round1 samples the local nonces and publishes the first signing commitments.
func (s *Cosigner[P, B, S]) Round1() (*Round1Broadcast[P, B, S], network.OutgoingUnicasts[*Round1P2P[P, B, S], *Cosigner[P, B, S]], error) {
	if s.state.round != 1 {
		return nil, nil, cggmp21.ErrInvalidRound.WithMessage("actual=%d expected=%d", s.state.round, 1)
	}
	if err := s.appendEpidToTranscript(); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot append epid to transcript")
	}

	zeroR1b, zeroR1u, err := s.zeroParty.Round1()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot run HJKY round 1")
	}
	auxInfo := s.shard.AuxInfo()

	// step 1.a
	k, err := algebrautils.RandomNonIdentity(s.params.ScalarField(), s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample k")
	}
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

	// step 1.b
	elgamalSecretKey, err := elgamal.SampleSecretKey(s.params.CurveGroup(), s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample ElGamal secret key")
	}
	bigY, err := indcpacom.NewHomomorphicCommitmentKey(elgamalSecretKey.Public())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create ElGamal commitment key")
	}
	kElgamalPlaintext, err := elgamal.NewPlaintext(s.params.CurveGroup().ScalarBaseMul(k))
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create ElGamal plaintext for k")
	}
	kElgamalMessage, err := indcpacom.NewMessage(kElgamalPlaintext)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create ElGamal commitment message for k")
	}
	a, err := bigY.SampleWitness(s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample ElGamal commitment witness for k")
	}
	bigA, err := bigY.CommitWithWitness(kElgamalMessage, a)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot commit ElGamal plaintext for k")
	}
	gammaElgamalPlaintext, err := elgamal.NewPlaintext(s.params.CurveGroup().ScalarBaseMul(gamma))
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create ElGamal plaintext for gamma")
	}
	gammaElgamalMessage, err := indcpacom.NewMessage(gammaElgamalPlaintext)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create ElGamal commitment message for gamma")
	}
	b, err := bigY.SampleWitness(s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample ElGamal commitment witness for gamma")
	}
	bigB, err := bigY.CommitWithWitness(gammaElgamalMessage, b)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot commit ElGamal plaintext for gamma")
	}

	// step 1.c
	psi0 := make(map[sharing.ID]compiler.NIZKPoKProof)
	psi1 := make(map[sharing.ID]compiler.NIZKPoKProof)
	for j := range s.ctx.OtherPartiesOrdered() {
		proof0, err := s.proveEncElg(j, k, bigK, rho, a, bigY, bigA)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot prove enc-elg for k to %d", j)
		}
		proof1, err := s.proveEncElg(j, gamma, bigG, nu, b, bigY, bigB)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot prove enc-elg for gamma to %d", j)
		}

		psi0[j] = proof0
		psi1[j] = proof1
	}

	s.state.k = k
	s.state.bigKJ = map[sharing.ID]*paillier.Ciphertext{
		s.ctx.HolderID(): bigK,
	}
	s.state.gamma = gamma
	s.state.rho = rho
	s.state.nu = nu
	s.state.bigYJ = map[sharing.ID]*indcpacom.HomomorphicCommitmentKey[*elgamal.PublicKey[P, S], *elgamal.Plaintext[P, S], *elgamal.Nonce[S], *elgamal.Ciphertext[P, S], S]{
		s.ctx.HolderID(): bigY,
	}
	s.state.a = a
	s.state.b = b
	s.state.bigAJ = map[sharing.ID]*indcpacom.Commitment[*elgamal.Ciphertext[P, S]]{
		s.ctx.HolderID(): bigA,
	}
	s.state.bigBJ = map[sharing.ID]*indcpacom.Commitment[*elgamal.Ciphertext[P, S]]{
		s.ctx.HolderID(): bigB,
	}

	// step 2
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
			return nil, nil, cggmp21.ErrFailed.WithMessage("missing zero-party round 1 unicast for %d", id)
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

// Round2 verifies round 1 messages and sends the Paillier affine-product messages.
func (s *Cosigner[P, B, S]) Round2(
	r1b network.RoundMessages[*Round1Broadcast[P, B, S], *Cosigner[P, B, S]],
	r1u network.RoundMessages[*Round1P2P[P, B, S], *Cosigner[P, B, S]],
) (*Round2Broadcast[P, B, S], network.OutgoingUnicasts[*Round2P2P[P, B, S], *Cosigner[P, B, S]], error) {
	if s.state.round != 2 {
		return nil, nil, cggmp21.ErrInvalidRound.WithMessage("actual=%d expected=%d", s.state.round, 2)
	}
	if errB := network.ValidateIncomingMessages(s, s.ctx.OtherPartiesOrdered(), r1b); errB != nil {
		return nil, nil, errs.Wrap(errB).WithMessage("invalid round 1 broadcast messages")
	}
	if errU := network.ValidateIncomingMessages(s, s.ctx.OtherPartiesOrdered(), r1u); errU != nil {
		return nil, nil, errs.Wrap(errU).WithMessage("invalid round 1 P2P messages")
	}

	zeroR1b := hashmap.NewComparable[sharing.ID, *hjky.Round1Broadcast[P, S]]()
	zeroR1u := hashmap.NewComparable[sharing.ID, *hjky.Round1P2P[P, S]]()
	bigKJ := s.state.bigKJ
	for j := range s.ctx.OtherPartiesOrdered() {
		b, _ := r1b.Get(j)
		u, _ := r1u.Get(j)
		zeroR1b.Put(j, b.ZeroR1)
		zeroR1u.Put(j, u.ZeroR1)
		bigKJ[j] = b.BigK

		// step 1.a
		if err := s.verifyEncElg(j, b.BigK, b.BigY, b.BigA, u.Psi0); err != nil {
			return nil, nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, j).WithMessage("cannot verify enc-elg statement")
		}

		// step 1.b
		if err := s.verifyEncElg(j, b.BigG, b.BigY, b.BigB, u.Psi1); err != nil {
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
		return nil, nil, cggmp21.ErrFailed.WithMessage("missing local effective partial public key")
	}
	x := s.state.x.Add(zeroShift)

	// step 2.a
	bigGamma := s.params.CurveGroup().ScalarBaseMul(s.state.gamma)
	psi, err := s.proveElog(s.params.CurveGroup().Generator(), s.state.gamma, bigGamma, s.state.b, s.state.bigBJ[s.ctx.HolderID()], bigGamma)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot prove gamma elog statement")
	}

	r2b := &Round2Broadcast[P, B, S]{
		BigGamma: bigGamma,
		Psi:      psi,
	}

	bigYJ := make(map[sharing.ID]*indcpacom.HomomorphicCommitmentKey[*elgamal.PublicKey[P, S], *elgamal.Plaintext[P, S], *elgamal.Nonce[S], *elgamal.Ciphertext[P, S], S])
	for id, bigY := range s.state.bigYJ {
		bigYJ[id] = bigY
	}
	localPaillierPublicKey := s.shard.AuxInfo().PaillierSecretKey().Public()
	betaJ := make(map[sharing.ID]*num.Int)
	betaHatJ := make(map[sharing.ID]*num.Int)
	rJ := make(map[sharing.ID]*paillier.Nonce)
	sJ := make(map[sharing.ID]*paillier.Nonce)
	rHatJ := make(map[sharing.ID]*paillier.Nonce)
	sHatJ := make(map[sharing.ID]*paillier.Nonce)
	bigDSentJ := make(map[sharing.ID]*paillier.Ciphertext)
	bigFSentJ := make(map[sharing.ID]*paillier.Ciphertext)
	bigDHatSentJ := make(map[sharing.ID]*paillier.Ciphertext)
	bigFHatSentJ := make(map[sharing.ID]*paillier.Ciphertext)
	r2u := hashmap.NewComparable[sharing.ID, *Round2P2P[P, B, S]]()
	for j := range s.ctx.OtherPartiesOrdered() {
		b, _ := r1b.Get(j)
		bigYJ[j] = b.BigY
		bigKj := bigKJ[j]

		// step 2.b
		paillierPublicKey, ok := s.shard.AuxInfo().PaillierPublicKey(j)
		if !ok {
			return nil, nil, cggmp21.ErrValidationFailed.WithMessage("missing Paillier public key for %d", j)
		}
		beta, err := sampleMask(s.params.LPrime(), s.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot sample beta for %d", j)
		}
		betaJ[j] = beta
		bigDJ, bigFJ, sNonce, rNonce, err := paillierMaskedProduct(paillierPublicKey, localPaillierPublicKey, bigKj, s.state.gamma, beta, s.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, j).WithMessage("cannot compute masked gamma product for %d", j)
		}
		betaHat, err := sampleMask(s.params.LPrime(), s.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot sample beta-hat for %d", j)
		}
		betaHatJ[j] = betaHat

		// step 2.b.i, 2.b.ii
		bigDHatJ, bigFHatJ, sHatNonce, rHatNonce, err := paillierMaskedProduct(paillierPublicKey, localPaillierPublicKey, bigKj, x, betaHat, s.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, j).WithMessage("cannot compute masked x product for %d", j)
		}

		// step 2.b.iii
		affgPsi, err := s.proveAffG(j, s.state.gamma, beta, sNonce, rNonce, bigKj, bigDJ, bigFJ, bigGamma)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot prove affg statement for %d", j)
		}

		// step 2.b.iv
		affgPsiHat, err := s.proveAffG(j, x, betaHat, sHatNonce, rHatNonce, bigKj, bigDHatJ, bigFHatJ, bigX)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot prove affg-hat statement for %d", j)
		}

		rJ[j] = rNonce
		sJ[j] = sNonce
		rHatJ[j] = rHatNonce
		sHatJ[j] = sHatNonce
		bigDSentJ[j] = bigDJ
		bigFSentJ[j] = bigFJ
		bigDHatSentJ[j] = bigDHatJ
		bigFHatSentJ[j] = bigFHatJ
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
	s.state.rJ = rJ
	s.state.sJ = sJ
	s.state.rHatJ = rHatJ
	s.state.sHatJ = sHatJ
	s.state.bigKJ = bigKJ
	s.state.bigDSentJ = bigDSentJ
	s.state.bigFSentJ = bigFSentJ
	s.state.bigDHatSentJ = bigDHatSentJ
	s.state.bigFHatSentJ = bigFHatSentJ
	s.state.bigDReceivedJ = make(map[sharing.ID]*paillier.Ciphertext)
	s.state.bigFReceivedJ = make(map[sharing.ID]*paillier.Ciphertext)
	s.state.bigDHatReceivedJ = make(map[sharing.ID]*paillier.Ciphertext)
	s.state.bigFHatReceivedJ = make(map[sharing.ID]*paillier.Ciphertext)
	s.state.partialPublicKeys = partialPublicKeys
	s.state.x = x
	s.state.round1Broadcasts = round1Broadcasts
	s.state.round2Broadcasts = map[sharing.ID]*Round2Broadcast[P, B, S]{
		s.ctx.HolderID(): r2b,
	}
	s.state.bigGammaJ = map[sharing.ID]P{
		s.ctx.HolderID(): bigGamma,
	}

	s.state.round++
	return r2b, r2u.Freeze(), nil
}

// Round3 verifies round 2 messages and publishes this party's delta contribution.
func (s *Cosigner[P, B, S]) Round3(
	r2b network.RoundMessages[*Round2Broadcast[P, B, S], *Cosigner[P, B, S]],
	r2u network.RoundMessages[*Round2P2P[P, B, S], *Cosigner[P, B, S]],
) (*Round3Broadcast[P, B, S], error) {
	if s.state.round != 3 {
		return nil, cggmp21.ErrInvalidRound.WithMessage("actual=%d expected=%d", s.state.round, 3)
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
	gammaInt, err := num.Z().FromUnsignedNumeric(s.state.gamma)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert gamma to integer")
	}
	kInt, err := num.Z().FromUnsignedNumeric(s.state.k)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert k to integer")
	}
	xInt, err := num.Z().FromUnsignedNumeric(s.state.x)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert x to integer")
	}
	deltaInt := gammaInt.Mul(kInt)
	chiInt := kInt.Mul(xInt)
	bigGammaJ := map[sharing.ID]P{
		s.ctx.HolderID(): bigGamma,
	}
	for j := range s.ctx.OtherPartiesOrdered() {
		b, _ := r2b.Get(j)
		u, _ := r2u.Get(j)
		s.state.bigDReceivedJ[j] = u.BigD
		s.state.bigFReceivedJ[j] = u.BigF
		s.state.bigDHatReceivedJ[j] = u.BigDHat
		s.state.bigFHatReceivedJ[j] = u.BigFHat
		bigGammaJ[j] = b.BigGamma

		// step 1.a
		if err := s.verifyAffG(j, u.BigD, u.BigF, b.BigGamma, u.Psi); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, j).WithMessage("cannot verify affg statement")
		}
		bigXJ, ok := s.state.partialPublicKeys[j]
		if !ok {
			return nil, cggmp21.ErrFailed.WithMessage("missing effective partial public key for %d", j)
		}

		// step 1.b
		if err := s.verifyAffG(j, u.BigDHat, u.BigFHat, bigXJ, u.PsiHat); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, j).WithMessage("cannot verify affg-hat statement")
		}

		// step 1.c
		if err := s.verifyElog(j, s.params.CurveGroup().Generator(), s.state.bigBJ[j], b.BigGamma, b.Psi); err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, j).WithMessage("cannot verify gamma elog statement")
		}
		bigGamma = bigGamma.Add(b.BigGamma)

		// step 2.a
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
		deltaInt = deltaInt.Add(alphaJ.Normalise()).Add(s.state.betaJ[j])
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
		chiInt = chiInt.Add(alphaHatJ.Normalise()).Add(s.state.betaHatJ[j])
	}

	if bigGamma.IsZero() {
		return nil, cggmp21.ErrFailed.WithMessage("aggregate Gamma is the identity element; signing must be retried")
	}

	round2Broadcasts, err := collectAndAppendBroadcastMessages(s, round2BroadcastTranscriptLabel, s.state.round2Broadcasts[s.ctx.HolderID()], r2b)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot append round 2 broadcasts to transcript")
	}

	bigDelta := bigGamma.ScalarMul(s.state.k)
	bigS := bigGamma.ScalarMul(chi)

	// step 2.b
	psiPrime, err := s.proveElog(bigGamma, s.state.k, s.params.CurveGroup().ScalarBaseMul(s.state.k), s.state.a, s.state.bigAJ[s.ctx.HolderID()], bigDelta)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot prove k elog statement")
	}

	s.state.delta = delta
	s.state.deltaInt = deltaInt
	s.state.chi = chi
	s.state.chiInt = chiInt
	s.state.bigGamma = bigGamma
	s.state.bigGammaJ = bigGammaJ
	s.state.bigDeltaJ = map[sharing.ID]P{
		s.ctx.HolderID(): bigDelta,
	}
	s.state.bigSJ = map[sharing.ID]P{
		s.ctx.HolderID(): bigS,
	}

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

// Round4 verifies round 3 messages and returns either a partial signature or a red-alert participant.
func (s *Cosigner[P, B, S]) Round4(r3b network.RoundMessages[*Round3Broadcast[P, B, S], *Cosigner[P, B, S]], message []byte) (*cggmp21.PartialSignature[P, B, S], *RedAlertParticipant[P, B, S], error) {
	if s.state.round != 4 {
		return nil, nil, cggmp21.ErrInvalidRound.WithMessage("actual=%d expected=%d", s.state.round, 4)
	}
	if err := network.ValidateIncomingMessages(s, s.ctx.OtherPartiesOrdered(), r3b); err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("invalid round 3 broadcast messages")
	}

	delta := s.state.delta
	bigDeltaSum := s.state.bigDeltaJ[s.ctx.HolderID()]
	bigSSum := s.state.bigSJ[s.ctx.HolderID()]
	bigDeltaJ := make(map[sharing.ID]P)
	bigDeltaJ[s.ctx.HolderID()] = bigDeltaSum
	deltaJ := make(map[sharing.ID]S)
	deltaJ[s.ctx.HolderID()] = s.state.delta
	bigSJ := make(map[sharing.ID]P)
	bigSJ[s.ctx.HolderID()] = bigSSum
	for id := range s.ctx.OtherPartiesOrdered() {
		b, _ := r3b.Get(id)
		delta = delta.Add(b.Delta)
		bigDeltaSum = bigDeltaSum.Add(b.BigDelta)
		bigSSum = bigSSum.Add(b.BigS)
		bigDeltaJ[id] = b.BigDelta
		deltaJ[id] = b.Delta
		bigSJ[id] = b.BigS

		// step 1.a
		if err := s.verifyElog(id, s.state.bigGamma, s.state.bigAJ[id], b.BigDelta, b.Psi); err != nil {
			return nil, nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot verify elog statement")
		}
	}

	round3Broadcasts, err := collectAndAppendBroadcastMessages(s, round3BroadcastTranscriptLabel, s.state.round3Broadcasts[s.ctx.HolderID()], r3b)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot append round 3 broadcasts to transcript")
	}

	s.state.bigDeltaJ = bigDeltaJ
	s.state.deltaJ = deltaJ
	s.state.bigSJ = bigSJ
	s.state.round3Broadcasts = round3Broadcasts

	// step 2.a
	if !s.params.CurveGroup().ScalarBaseMul(delta).Equal(bigDeltaSum) {
		return nil, newRedAlertNonce(s), nil
	}
	if !s.shard.PublicKeyValue().ScalarMul(delta).Equal(bigSSum) {
		return nil, newRedAlertChi(s), nil
	}

	deltaInv, err := delta.TryInv()
	if err != nil {
		return nil, nil, errs.Join(err, base.ErrAbort).WithMessage("cannot invert delta")
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
		return nil, nil, errs.Wrap(err).WithMessage("cannot hash signing message")
	}
	m, err := sigecdsa.DigestToScalar(s.params.ScalarField(), digest)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot convert digest to scalar")
	}
	rx, err := s.state.bigGamma.AffineX()
	if err != nil {
		return nil, nil, errs.Join(err, base.ErrAbort).WithMessage("cannot get Gamma affine x-coordinate")
	}
	r, err := s.params.ScalarField().FromWideBytes(rx.Bytes())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot convert Gamma x-coordinate to scalar")
	}
	sigma := kTilde.Mul(m).Add(r.Mul(chiTilde))

	s.state.bigDeltaTildeJ = bigDeltaTildeJ
	s.state.bigSTildeJ = bigSTildeJ
	s.state.m = m
	partialSignature := &cggmp21.PartialSignature[P, B, S]{
		Gamma: s.state.bigGamma,
		Sigma: sigma,
	}

	s.state.round++
	return partialSignature, nil, nil
}

func (s *Cosigner[P, B, S]) appendEpidToTranscript() error {
	s.ctx.Transcript().AppendBytes(publicKeyValueLabel, s.shard.PublicKey().Value().Bytes())
	s.ctx.Transcript().AppendBytes(ridLabel, s.shard.AuxInfo().RefreshID())

	var paillierPk *paillier.PublicKey
	var ringPedersenPk *intcom.CommitmentKey
	for id := range s.ctx.AllPartiesOrdered() {
		if id == s.ctx.HolderID() {
			paillierPk = s.shard.AuxInfo().PaillierSecretKey().Public()
			ringPedersenPk = s.shard.AuxInfo().RingPedersenSecretKey().Export()
		} else {
			var ok bool
			paillierPk, ok = s.shard.AuxInfo().PaillierPublicKeys()[id]
			if !ok {
				return cggmp21.ErrFailed.WithMessage("internal error: missing Paillier key")
			}
			ringPedersenPk, ok = s.shard.AuxInfo().RingPedersenPublicKeys()[id]
			if !ok {
				return cggmp21.ErrFailed.WithMessage("internal error: missing RingPedersen key")
			}
		}

		s.ctx.Transcript().AppendBytes(paillierPublicKeyLabel, id.Bytes(), paillierPk.PlaintextGroup().Modulus().Bytes())
		s.ctx.Transcript().AppendBytes(ringPedersenPublicKeyLabel, id.Bytes(), ringPedersenPk.Group().Modulus().Bytes())
		s.ctx.Transcript().AppendBytes(sLabel, id.Bytes(), ringPedersenPk.S().Bytes())
		s.ctx.Transcript().AppendBytes(tLabel, id.Bytes(), ringPedersenPk.T().Bytes())
	}

	return nil
}

func (s *Cosigner[P, B, S]) proveEncElg(
	recipient sharing.ID,
	value S,
	paillierCiphertext *paillier.Ciphertext,
	paillierNonce *paillier.Nonce,
	elgamalWitness *indcpacom.Witness[*elgamal.Nonce[S]],
	elgamalCommitmentKey *indcpacom.HomomorphicCommitmentKey[
		*elgamal.PublicKey[P, S],
		*elgamal.Plaintext[P, S],
		*elgamal.Nonce[S],
		*elgamal.Ciphertext[P, S],
		S,
	],
	elgamalCommitment *indcpacom.Commitment[*elgamal.Ciphertext[P, S]],
) (compiler.NIZKPoKProof, error) {
	encElgSigma, err := encelg.NewProtocol(s.shard.AuxInfo().RingPedersenPublicKeys()[recipient], elgamalCommitmentKey, s.params.L(), s.params.Epsilon(), s.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create enc-elg protocol")
	}
	encElg, err := fiatshamir.NewCompiler(encElgSigma)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create NI enc-elg protocol")
	}
	proverCtx, err := s.ctx.SubContext(hashset.NewComparable(s.ctx.HolderID(), recipient).Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create subcontext")
	}
	proverCtx.Transcript().AppendBytes(proverID, s.shard.Share().ID().Bytes())
	prover, err := encElg.NewProver(proverCtx)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create enc-elg prover")
	}

	valueInt, err := num.Z().FromUnsignedNumeric(value)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert scalar to integer")
	}
	witness, err := encelg.NewWitness[S](valueInt, paillierNonce, elgamalWitness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create enc-elg witness")
	}
	statement, err := encelg.NewStatement(s.shard.AuxInfo().PaillierSecretKey().Public(), paillierCiphertext, elgamalCommitment)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create enc-elg statement")
	}
	proof, err := prover.Prove(statement, witness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create enc-elg proof")
	}
	return proof, nil
}

func (s *Cosigner[P, B, S]) verifyEncElg(
	sender sharing.ID,
	paillierCiphertext *paillier.Ciphertext,
	elgamalCommitmentKey *indcpacom.HomomorphicCommitmentKey[
		*elgamal.PublicKey[P, S],
		*elgamal.Plaintext[P, S],
		*elgamal.Nonce[S],
		*elgamal.Ciphertext[P, S],
		S,
	],
	elgamalCommitment *indcpacom.Commitment[*elgamal.Ciphertext[P, S]],
	proof compiler.NIZKPoKProof,
) error {
	encElgSigma, err := encelg.NewProtocol(s.shard.AuxInfo().RingPedersenSecretKey().Export(), elgamalCommitmentKey, s.params.L(), s.params.Epsilon(), s.prng)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create enc-elg protocol")
	}
	encElg, err := fiatshamir.NewCompiler(encElgSigma)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create NI enc-elg protocol")
	}
	verifierCtx, err := s.ctx.SubContext(hashset.NewComparable(sender, s.ctx.HolderID()).Freeze())
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create subcontext")
	}
	verifierCtx.Transcript().AppendBytes(proverID, sender.Bytes())
	verifier, err := encElg.NewVerifier(verifierCtx)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create enc-elg verifier")
	}
	paillierPublicKey, err := paillierPublicKeyFor(s, sender)
	if err != nil {
		return err
	}
	statement, err := encelg.NewStatement(paillierPublicKey, paillierCiphertext, elgamalCommitment)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create enc-elg statement")
	}
	if err := verifier.Verify(statement, proof); err != nil {
		return errs.Wrap(err).WithMessage("enc-elg proof failed")
	}
	return nil
}

func (s *Cosigner[P, B, S]) proveElog(
	basePoint P,
	witnessScalar S,
	elgamalPlaintextPoint P,
	elgamalWitness *indcpacom.Witness[*elgamal.Nonce[S]],
	elgamalCommitment *indcpacom.Commitment[*elgamal.Ciphertext[P, S]],
	statementPoint P,
) (compiler.NIZKPoKProof, error) {
	elgamalCommitmentKey := s.state.bigYJ[s.ctx.HolderID()]
	if elgamalCommitmentKey == nil {
		return nil, cggmp21.ErrNil.WithMessage("local ElGamal commitment key")
	}
	elogCk := &elgamalCommitmentKey.CommitmentKey
	elogSigma, err := elog.NewProtocol(s.params.CurveGroup(), elogCk, basePoint, s.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create elog protocol")
	}
	elogNI, err := fiatshamir.NewCompiler(elogSigma)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create NI elog protocol")
	}
	elgamalPlaintext, err := elgamal.NewPlaintext(elgamalPlaintextPoint)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create ElGamal plaintext")
	}
	elgamalMessage, err := indcpacom.NewMessage(elgamalPlaintext)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create ElGamal message")
	}
	elcomopWitness, err := elcomop.NewWitness(elgamalMessage, elgamalWitness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create elcomop witness")
	}
	schWitness := schnorr.NewWitness(witnessScalar)
	elogWitness, err := elog.NewWitness(elcomopWitness, schWitness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create elog witness")
	}
	elcomopStatement, err := elcomop.NewStatement(elgamalCommitment)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create elcomop statement")
	}
	schStatement := schnorr.NewStatement(statementPoint)
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
	proof, err := elogProver.Prove(elogStatement, elogWitness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create elog proof")
	}
	return proof, nil
}

func (s *Cosigner[P, B, S]) verifyElog(
	sender sharing.ID,
	basePoint P,
	elgamalCommitment *indcpacom.Commitment[*elgamal.Ciphertext[P, S]],
	statementPoint P,
	proof compiler.NIZKPoKProof,
) error {
	elgamalCommitmentKey := s.state.bigYJ[sender]
	if elgamalCommitmentKey == nil {
		return cggmp21.ErrNil.WithMessage("ElGamal commitment key for %d", sender)
	}
	elogCk := &elgamalCommitmentKey.CommitmentKey
	elogSigma, err := elog.NewProtocol(s.params.CurveGroup(), elogCk, basePoint, s.prng)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create elog protocol")
	}
	elogNI, err := fiatshamir.NewCompiler(elogSigma)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create NI elog protocol")
	}
	elcomopStatement, err := elcomop.NewStatement(elgamalCommitment)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create elcomop statement")
	}
	schStatement := schnorr.NewStatement(statementPoint)
	elogStatement, err := elog.NewStatement(elcomopStatement, schStatement)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create elog statement")
	}
	elogVerifierCtx := s.ctx.Clone()
	elogVerifierCtx.Transcript().AppendBytes(proverID, sender.Bytes())
	elogVerifier, err := elogNI.NewVerifier(elogVerifierCtx)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create elog verifier")
	}
	if err := elogVerifier.Verify(elogStatement, proof); err != nil {
		return errs.Wrap(err).WithMessage("elog proof failed")
	}
	return nil
}

func (s *Cosigner[P, B, S]) proveAffG(
	recipient sharing.ID,
	x S,
	beta *num.Int,
	rho *paillier.Nonce,
	rhoY *paillier.Nonce,
	c *paillier.Ciphertext,
	d *paillier.Ciphertext,
	y *paillier.Ciphertext,
	bigX P,
) (compiler.NIZKPoKProof, error) {
	recipientPaillierPublicKey, ok := s.shard.AuxInfo().PaillierPublicKey(recipient)
	if !ok {
		return nil, cggmp21.ErrValidationFailed.WithMessage("missing Paillier public key for %d", recipient)
	}
	localPaillierPublicKey := s.shard.AuxInfo().PaillierSecretKey().Public()
	affgSigma, err := affg.NewProtocol(s.shard.AuxInfo().RingPedersenPublicKeys()[recipient], s.params.L(), s.params.LPrime(), s.params.Epsilon(), s.params.CurveGroup(), s.prng)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create affg protocol")
	}
	affgNI, err := fiatshamir.NewCompiler(affgSigma)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create NI affg compiler")
	}
	affgProverCtx, err := s.ctx.SubContext(hashset.NewComparable(s.ctx.HolderID(), recipient).Freeze())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create subcontext")
	}
	affgProverCtx.Transcript().AppendBytes(proverID, s.ctx.HolderID().Bytes())
	affgProver, err := affgNI.NewProver(affgProverCtx)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create affg prover")
	}

	xInt, err := num.Z().FromUnsignedNumeric(x)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert scalar to integer")
	}
	betaPlaintext, err := paillier.NewPlaintextSymmetric(beta.Neg(), localPaillierPublicKey.PlaintextGroup().Modulus())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create beta plaintext")
	}
	rhoYInv, err := localPaillierPublicKey.NonceOpInv(rhoY)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot invert beta nonce")
	}
	yInv, err := localPaillierPublicKey.CiphertextOpInv(y)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot invert BigF")
	}
	affgWitness, err := affg.NewWitness(xInt, betaPlaintext, rho, rhoYInv)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create affg witness")
	}
	affgStatement, err := affg.NewStatement(recipientPaillierPublicKey, localPaillierPublicKey, c, d, yInv, bigX)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create affg statement")
	}
	proof, err := affgProver.Prove(affgStatement, affgWitness)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot create affg proof")
	}
	return proof, nil
}

func (s *Cosigner[P, B, S]) verifyAffG(
	sender sharing.ID,
	d *paillier.Ciphertext,
	y *paillier.Ciphertext,
	bigX P,
	proof compiler.NIZKPoKProof,
) error {
	localPaillierPublicKey := s.shard.AuxInfo().PaillierSecretKey().Public()
	senderPaillierPublicKey, ok := s.shard.AuxInfo().PaillierPublicKey(sender)
	if !ok {
		return cggmp21.ErrValidationFailed.WithMessage("missing Paillier public key for %d", sender)
	}
	affgSigma, err := affg.NewProtocol(s.shard.AuxInfo().RingPedersenSecretKey().Export(), s.params.L(), s.params.LPrime(), s.params.Epsilon(), s.params.CurveGroup(), s.prng)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create affg protocol")
	}
	affgNI, err := fiatshamir.NewCompiler(affgSigma)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create NI affg compiler")
	}
	affgVerifierCtx, err := s.ctx.SubContext(hashset.NewComparable(sender, s.ctx.HolderID()).Freeze())
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create subcontext")
	}
	affgVerifierCtx.Transcript().AppendBytes(proverID, sender.Bytes())
	affgVerifier, err := affgNI.NewVerifier(affgVerifierCtx)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create affg verifier")
	}

	yInv, err := senderPaillierPublicKey.CiphertextOpInv(y)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot invert BigF")
	}
	statement, err := affg.NewStatement(localPaillierPublicKey, senderPaillierPublicKey, s.state.bigKJ[s.ctx.HolderID()], d, yInv, bigX)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot create affg statement")
	}
	if err := affgVerifier.Verify(statement, proof); err != nil {
		return errs.Wrap(err).WithMessage("aff-g proof failed")
	}
	return nil
}

func (s *Cosigner[P, B, S]) aggregate(partialSignatures map[sharing.ID]*cggmp21.PartialSignature[P, B, S]) (*sigecdsa.Signature[S], error) {
	if s.state.round != 5 {
		return nil, cggmp21.ErrInvalidRound.WithMessage("actual=%d expected=%d", s.state.round, 5)
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
