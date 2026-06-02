package signing

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
	"github.com/bronlabs/bron-crypto/pkg/mpc/zero/hjky"
	"github.com/bronlabs/bron-crypto/pkg/network"
	sigecdsa "github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func (s *Signer[P, B, S]) Round1() (*Round1Broadcast[P, B, S], network.OutgoingUnicasts[*Round1P2P[P, B, S], *Signer[P, B, S]], error) {
	if s.state.round != 1 {
		return nil, nil, ErrInvalidRound.WithMessage("actual=%d expected=%d", s.state.round, 1)
	}

	k, err := algebrautils.RandomNonIdentity(s.scalarField, s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample k")
	}
	auxInfo := s.shard.AuxInfo()
	bigK, rho, err := paillierEncryptScalar(auxInfo.PaillierSecretKey(), k, s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot encrypt k")
	}

	gamma, err := algebrautils.RandomNonIdentity(s.scalarField, s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample gamma")
	}
	bigG, nu, err := paillierEncryptScalar(auxInfo.PaillierSecretKey(), gamma, s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot encrypt gamma")
	}

	elgamalSecretKey, err := elgamal.SampleSecretKey(s.curveGroup, s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot sample ElGamal secret key")
	}
	bigY := elgamalSecretKey.Public()
	kElgamalPlaintext, err := elgamal.NewPlaintext(s.curveGroup.ScalarBaseMul(k))
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create ElGamal plaintext for k")
	}
	bigA, a, err := encryption.Encrypt(kElgamalPlaintext, bigY, s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot encrypt ElGamal plaintext for k")
	}
	gammaElgamalPlaintext, err := elgamal.NewPlaintext(s.curveGroup.ScalarBaseMul(gamma))
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot create ElGamal plaintext for gamma")
	}
	bigB, b, err := encryption.Encrypt(gammaElgamalPlaintext, bigY, s.prng)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot encrypt ElGamal plaintext for gamma")
	}

	zeroR1b, zeroR1u, err := s.zeroParty.Round1()
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot run HJKY round 1")
	}

	s.state.k = k
	s.state.gamma = gamma
	s.state.rho = rho
	s.state.nu = nu
	s.state.bigYJ = make(map[sharing.ID]*elgamal.PublicKey[P, S])
	s.state.bigYJ[s.ctx.HolderID()] = bigY
	s.state.a = a
	s.state.b = b
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
	round1Broadcasts, err := collectAndAppendBroadcastMessages(s, round1BroadcastTranscriptLabel, s.state.round1Broadcasts[s.ctx.HolderID()], r1b)
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot append round 1 broadcasts to transcript")
	}

	zeroR1b := hashmap.NewComparable[sharing.ID, *hjky.Round1Broadcast[P, S]]()
	zeroR1u := hashmap.NewComparable[sharing.ID, *hjky.Round1P2P[P, S]]()
	for id := range s.ctx.OtherPartiesOrdered() {
		b, _ := r1b.Get(id)
		u, _ := r1u.Get(id)
		zeroR1b.Put(id, b.ZeroR1)
		zeroR1u.Put(id, u.ZeroR1)
	}
	shiftShare, _, err := s.zeroParty.Round2(zeroR1b.Freeze(), zeroR1u.Freeze())
	if err != nil {
		return nil, nil, errs.Wrap(err).WithMessage("cannot compute zero-party round 2")
	}
	if shiftShare == nil || len(shiftShare.Value()) != 1 {
		return nil, nil, ErrFailed.WithMessage("zero-party round 2 returned invalid shift share")
	}
	x := s.state.x.Add(shiftShare.Value()[0])

	bigGamma := s.curveGroup.ScalarBaseMul(s.state.gamma)
	r2b := &Round2Broadcast[P, B, S]{
		BigGamma: bigGamma,
	}

	bigYJ := make(map[sharing.ID]*elgamal.PublicKey[P, S])
	for id, bigY := range s.state.bigYJ {
		bigYJ[id] = bigY
	}
	betaJ := make(map[sharing.ID]*num.Int)
	betaHatJ := make(map[sharing.ID]*num.Int)
	r2u := hashmap.NewComparable[sharing.ID, *Round2P2P[P, B, S]]()
	for id := range s.ctx.OtherPartiesOrdered() {
		b, _ := r1b.Get(id)
		bigYJ[id] = b.BigY
		bigKj := b.BigK
		paillierPublicKey, ok := s.shard.AuxInfo().PaillierPublicKey(id)
		if !ok {
			return nil, nil, cggmp21.ErrValidationFailed.WithMessage("missing Paillier public key for %d", id)
		}

		beta, err := sampleMask(s.params.LPrime(), s.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot sample beta for %d", id)
		}
		bigDJ, bigFJ, err := paillierMaskedProduct(paillierPublicKey, bigKj, s.state.gamma, beta, s.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot compute masked gamma product for %d", id)
		}

		betaHat, err := sampleMask(s.params.LPrime(), s.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithMessage("cannot sample beta-hat for %d", id)
		}
		bigDHatJ, bigFHatJ, err := paillierMaskedProduct(paillierPublicKey, bigKj, x, betaHat, s.prng)
		if err != nil {
			return nil, nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot compute masked x product for %d", id)
		}

		betaJ[id] = beta
		betaHatJ[id] = betaHat
		r2u.Put(id, &Round2P2P[P, B, S]{
			BigD:    bigDJ,
			BigF:    bigFJ,
			BigDHat: bigDHatJ,
			BigFHat: bigFHatJ,
		})
	}

	s.state.bigYJ = bigYJ
	s.state.betaJ = betaJ
	s.state.betaHatJ = betaHatJ
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
	round2Broadcasts, err := collectAndAppendBroadcastMessages(s, round2BroadcastTranscriptLabel, s.state.round2Broadcasts[s.ctx.HolderID()], r2b)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot append round 2 broadcasts to transcript")
	}

	bigGamma := s.curveGroup.ScalarBaseMul(s.state.gamma)
	delta := s.state.gamma.Mul(s.state.k)
	chi := s.state.k.Mul(s.state.x)
	for id := range s.ctx.OtherPartiesOrdered() {
		b, _ := r2b.Get(id)
		u, _ := r2u.Get(id)
		bigGamma = bigGamma.Add(b.BigGamma)

		alphaJ, err := s.shard.AuxInfo().PaillierSecretKey().Decrypt(u.BigD)
		if err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot decrypt BigD from %d", id)
		}
		alphaScalar, err := paillierPlaintextToScalar(alphaJ, s.scalarField)
		if err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot convert BigD plaintext from %d", id)
		}
		betaScalar, err := intToScalar(s.state.betaJ[id], s.scalarField)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot convert local beta for %d", id)
		}
		delta = delta.Add(alphaScalar).Add(betaScalar)

		alphaHatJ, err := s.shard.AuxInfo().PaillierSecretKey().Decrypt(u.BigDHat)
		if err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot decrypt BigDHat from %d", id)
		}
		alphaHatScalar, err := paillierPlaintextToScalar(alphaHatJ, s.scalarField)
		if err != nil {
			return nil, errs.Wrap(err).WithTag(base.IdentifiableAbortPartyIDTag, id).WithMessage("cannot convert BigDHat plaintext from %d", id)
		}
		betaHatScalar, err := intToScalar(s.state.betaHatJ[id], s.scalarField)
		if err != nil {
			return nil, errs.Wrap(err).WithMessage("cannot convert local beta-hat for %d", id)
		}
		chi = chi.Add(alphaHatScalar).Add(betaHatScalar)
	}
	bigDelta := bigGamma.ScalarMul(s.state.k)
	bigS := bigGamma.ScalarMul(chi)

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
	round3Broadcasts, err := collectAndAppendBroadcastMessages(s, round3BroadcastTranscriptLabel, s.state.round3Broadcasts[s.ctx.HolderID()], r3b)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot append round 3 broadcasts to transcript")
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
	}

	// verification
	if !s.curveGroup.ScalarBaseMul(delta).Equal(bigDeltaSum) {
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
	m, err := sigecdsa.DigestToScalar(s.scalarField, digest)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot convert digest to scalar")
	}
	rx, err := s.state.bigGamma.AffineX()
	if err != nil {
		return nil, errs.Join(err, base.ErrAbort).WithMessage("cannot get Gamma affine x-coordinate")
	}
	r, err := s.scalarField.FromWideBytes(rx.Bytes())
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
	r, err := s.scalarField.FromWideBytes(rx.Bytes())
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
