package vsot

import (
	"bytes"
	"crypto/subtle"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	dlogschnorr "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

func (s *Sender[P, B, S]) Round1() (*Round1P2P[P, B, S], error) {
	var err error

	s.state.b, err = s.field.Random(s.prng)
	if err != nil {
		return nil, errs.WrapRandomSample(err, "generating b")
	}
	s.state.bigB = s.curve.ScalarBaseMul(s.state.b)

	dlogProtocol, err := dlogschnorr.NewSigmaProtocol(s.curve.Generator(), s.prng)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog protocol")
	}
	dlogProtocolCompiler, err := fiatshamir.NewCompiler(dlogProtocol)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog protocol compiler")
	}
	// TODO: would be nice to have dlogschnorr.NewStatement(G, P)
	dlogStatement := &dlogschnorr.Statement[P, S]{
		X:   s.state.bigB,
		Phi: dlogschnorr.Phi(s.curve.Generator()),
	}
	// TODO: would be nice to have dlogschnorr.NewWitness(s)
	dlogWitness := &dlogschnorr.Witness[S]{
		W: s.state.b,
	}
	dlogProver, err := dlogProtocolCompiler.NewProver(s.sessionId, s.tape)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog prover")
	}
	dlogProof, err := dlogProver.Prove(dlogStatement, dlogWitness)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot create dlog proof")
	}
	// TODO: a lot of lines (~24) just to do PoK :(

	r1 := &Round1P2P[P, B, S]{
		bigB:  s.state.bigB,
		proof: dlogProof,
	}
	return r1, nil
}

func (r *Receiver[P, B, S]) Round2(r1 *Round1P2P[P, B, S], c []byte) (*Round2P2P[P, B, S], *ReceiverOutput, error) {
	// validation
	if r1.bigB.IsOpIdentity() {
		return nil, nil, errs.NewValidation("B is identity")
	}
	if len(c)*8 != r.chi {
		return nil, nil, errs.NewValidation("invalid choices length")
	}
	// TODO: generator is passed twice
	dlogProtocol, err := dlogschnorr.NewSigmaProtocol(r.curve.Generator(), r.prng)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create dlog protocol")
	}
	dlogProtocolCompiler, err := fiatshamir.NewCompiler(dlogProtocol)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create dlog protocol compiler")
	}
	// TODO: would be nice to have dlogschnorr.NewStatement(G, P)
	dlogStatement := &dlogschnorr.Statement[P, S]{
		X:   r1.bigB,
		Phi: dlogschnorr.Phi(r.curve.Generator()),
	}
	dlogVerifier, err := dlogProtocolCompiler.NewVerifier(r.sessionId, r.tape)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot create dlog verifier")
	}
	err = dlogVerifier.Verify(dlogStatement, r1.proof)
	if err != nil {
		return nil, nil, errs.WrapVerification(err, "verification failed")
	}

	r.state.omegaRaw = make([]uint64, r.chi)
	r.state.omega = make([]S, r.chi)
	r.state.rhoOmega = make([][]byte, r.chi)
	r.state.bigB = r1.bigB
	r.state.bigA = make([]P, r.chi)
	for i := range r.chi {
		a, err := r.field.Random(r.prng)
		if err != nil {
			return nil, nil, errs.WrapRandomSample(err, "generating a")
		}
		r.state.omegaRaw[i] = uint64((c[i/8] >> (i % 8)) & 0b1)
		r.state.omega[i] = r.field.FromUint64(r.state.omegaRaw[i])
		r.state.bigA[i] = r.curve.ScalarBaseMul(a).Add(r.state.bigB.ScalarMul(r.state.omega[i]))
		r.state.rhoOmega[i], err = r.hash(r.state.bigB, r.state.bigA[i], r.state.bigB.ScalarMul(a).ToCompressed())
		if err != nil {
			return nil, nil, errs.WrapHashing(err, "cannot hash B * a_i")
		}
	}

	receiverOutput := &ReceiverOutput{
		Choices: c,
		M:       r.state.rhoOmega,
	}

	r2 := &Round2P2P[P, B, S]{
		bigA: r.state.bigA,
	}
	return r2, receiverOutput, nil
}

func (s *Sender[P, B, S]) Round3(r2 *Round2P2P[P, B, S]) (*Round3P2P, *SenderOutput, error) {
	var err error
	if len(r2.bigA) != s.chi {
		return nil, nil, errs.NewValidation("invalid message")
	}

	rho0 := make([][]byte, s.chi)
	rho1 := make([][]byte, s.chi)
	s.state.rho0Digest = make([][]byte, s.chi)
	s.state.rho1Digest = make([][]byte, s.chi)
	s.state.rho0DigestDigest = make([][]byte, s.chi)
	xi := make([][]byte, s.chi)
	senderOutput := &SenderOutput{
		M: make([][2][]byte, s.chi),
	}
	for i, bigA := range r2.bigA {
		if bigA.IsOpIdentity() {
			return nil, nil, errs.NewValidation("A is identity")
		}

		rho0[i], err = s.hash(s.state.bigB, bigA, bigA.ScalarMul(s.state.b).ToCompressed())
		if err != nil {
			return nil, nil, errs.WrapHashing(err, "cannot hash A * b_i")
		}
		rho1[i], err = s.hash(s.state.bigB, bigA, (bigA.Sub(s.state.bigB)).ScalarMul(s.state.b).ToCompressed())
		if err != nil {
			return nil, nil, errs.WrapHashing(err, "cannot hash (A - B_i) * b_i")
		}
		senderOutput.M[i][0] = rho0[i]
		senderOutput.M[i][1] = rho1[i]

		s.state.rho0Digest[i], err = s.hash(s.state.bigB, bigA, rho0[i])
		if err != nil {
			return nil, nil, errs.WrapHashing(err, "cannot hash rho_0")
		}
		s.state.rho0DigestDigest[i], err = s.hash(s.state.bigB, bigA, s.state.rho0Digest[i])
		if err != nil {
			return nil, nil, errs.WrapHashing(err, "cannot hash rho_0 digest")
		}
		s.state.rho1Digest[i], err = s.hash(s.state.bigB, bigA, rho1[i])
		if err != nil {
			return nil, nil, errs.WrapHashing(err, "cannot hash rho_1")
		}
		rho1DigestDigest, err := s.hash(s.state.bigB, bigA, s.state.rho1Digest[i])
		if err != nil {
			return nil, nil, errs.WrapHashing(err, "cannot hash rho_1 digest")
		}
		xi[i] = make([]byte, len(s.state.rho0DigestDigest[i]))
		subtle.XORBytes(xi[i], s.state.rho0DigestDigest[i], rho1DigestDigest)
	}

	r3 := &Round3P2P{
		xi: xi,
	}
	return r3, senderOutput, nil
}

func (r *Receiver[P, B, S]) Round4(r3 *Round3P2P) (*Round4P2P, error) {
	var err error
	if len(r3.xi) != r.chi {
		return nil, errs.NewValidation("invalid message")
	}

	r.state.xi = r3.xi
	rhoPrime := make([][]byte, r.chi)
	r.state.rhoOmegaDigest = make([][]byte, r.chi)
	for i := range r.chi {
		if len(r3.xi[i]) != r.hashFunc().Size() {
			return nil, errs.NewValidation("invalid message")
		}

		r.state.rhoOmegaDigest[i], err = r.hash(r.state.bigB, r.state.bigA[i], r.state.rhoOmega[i])
		if err != nil {
			return nil, errs.WrapHashing(err, "cannot hash rho_omega")
		}
		rhoPrime[i], err = r.hash(r.state.bigB, r.state.bigA[i], r.state.rhoOmegaDigest[i])
		if err != nil {
			return nil, errs.WrapHashing(err, "cannot hash rho_omega digest")
		}
		xi := ct.SliceSelect(ct.Choice(r.state.omegaRaw[i]), make([]byte, len(r3.xi[i])), r3.xi[i])
		subtle.XORBytes(rhoPrime[i], rhoPrime[i], xi)
	}

	r4 := &Round4P2P{
		rhoPrime: rhoPrime,
	}
	return r4, nil
}

func (s *Sender[P, B, S]) Round5(r4 *Round4P2P) (*Round5P2P, error) {
	if len(r4.rhoPrime) != s.chi {
		return nil, errs.NewValidation("invalid message")
	}

	for i := range r4.rhoPrime {
		if len(r4.rhoPrime[i]) != s.hashFunc().Size() {
			return nil, errs.NewValidation("invalid message")
		}

		if !bytes.Equal(r4.rhoPrime[i], s.state.rho0DigestDigest[i]) {
			return nil, errs.NewTotalAbort("R", "verification failed")
		}
	}

	r5 := &Round5P2P{
		rho0Digest: s.state.rho0Digest,
		rho1Digest: s.state.rho1Digest,
	}
	return r5, nil
}

func (r *Receiver[P, B, S]) Round6(r5 *Round5P2P) error {
	if len(r5.rho0Digest) != r.chi || len(r5.rho1Digest) != r.chi {
		return errs.NewValidation("invalid message")
	}

	for i := range r.chi {
		rho0Digest := r5.rho0Digest[i]
		rho1Digest := r5.rho1Digest[i]
		if len(rho0Digest) != r.hashFunc().Size() || len(rho1Digest) != r.hashFunc().Size() {
			return errs.NewValidation("invalid message")
		}

		switch r.state.omegaRaw[i] {
		case 0:
			if !bytes.Equal(rho0Digest, r.state.rhoOmegaDigest[i]) {
				return errs.NewVerification("verification failed")
			}
		case 1:
			if !bytes.Equal(rho1Digest, r.state.rhoOmegaDigest[i]) {
				return errs.NewVerification("verification failed")
			}
		default:
			panic("invalid internal state - this should never happen")
		}

		rho0DigestDigest, err := r.hash(r.state.bigB, r.state.bigA[i], rho0Digest)
		if err != nil {
			return errs.WrapHashing(err, "cannot hash rho_0 digest")
		}
		rho1DigestDigest, err := r.hash(r.state.bigB, r.state.bigA[i], rho1Digest)
		if err != nil {
			return errs.WrapHashing(err, "cannot hash rho_1 digest")
		}
		xi := make([]byte, len(rho0DigestDigest))
		subtle.XORBytes(xi, rho0DigestDigest, rho1DigestDigest)
		if !bytes.Equal(xi, r.state.xi[i]) {
			return errs.NewVerification("verification failed")
		}
	}

	return nil
}
