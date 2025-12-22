package vsot

import (
	"crypto/subtle"
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	dlogschnorr "github.com/bronlabs/bron-crypto/pkg/proofs/dlog/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/fiatshamir"
)

// Round1 samples sender secret b, computes B = bG, proves knowledge of b, and sends (B, proof).
func (s *Sender[P, B, S]) Round1() (*Round1P2P[P, B, S], error) {
	var err error
	if s.round != 1 {
		return nil, ot.ErrRound.WithMessage("invalid round")
	}

	s.state.b, err = s.suite.Field().Random(s.prng)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("generating b")
	}
	s.state.bigB = s.suite.Curve().ScalarBaseMul(s.state.b)

	dlogProtocol, err := dlogschnorr.NewProtocol(s.suite.Curve().Generator(), s.prng)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create dlog protocol")
	}
	dlogProtocolCompiler, err := fiatshamir.NewCompiler(dlogProtocol)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create dlog protocol compiler")
	}
	// TODO: would be nice to have dlogschnorr.NewStatement(G, P)
	dlogStatement := &dlogschnorr.Statement[P, S]{
		X: s.state.bigB,
	}
	// TODO: would be nice to have dlogschnorr.NewWitness(s)
	dlogWitness := &dlogschnorr.Witness[S]{
		W: s.state.b,
	}
	dlogProver, err := dlogProtocolCompiler.NewProver(s.sessionId, s.tape)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create dlog prover")
	}
	dlogProof, err := dlogProver.Prove(dlogStatement, dlogWitness)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("cannot create dlog proof")
	}
	// TODO: a lot of lines (~24) just to do PoK :(

	r1 := &Round1P2P[P, B, S]{
		BigB:  s.state.bigB,
		Proof: dlogProof,
	}
	s.round += 2
	return r1, nil
}

// Round2 verifies the sender's proof, encodes receiver choices, and computes A values and receiver seeds.
func (r *Receiver[P, B, S]) Round2(r1 *Round1P2P[P, B, S], choices []byte) (*Round2P2P[P, B, S], *ReceiverOutput, error) {
	if r.round != 2 {
		return nil, nil, ot.ErrRound.WithMessage("invalid round")
	}
	if err := r1.Validate(); err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("invalid message")
	}
	if len(choices)*8 != r.suite.Xi() {
		return nil, nil, ot.ErrInvalidArgument.WithMessage("invalid choices length")
	}

	dlogProtocol, err := dlogschnorr.NewProtocol(r.suite.curve.Generator(), r.prng)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot create dlog protocol")
	}
	dlogProtocolCompiler, err := fiatshamir.NewCompiler(dlogProtocol)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot create dlog protocol compiler")
	}
	// TODO: would be nice to have dlogschnorr.NewStatement(G, P)
	dlogStatement := &dlogschnorr.Statement[P, S]{
		X: r1.BigB,
	}
	dlogVerifier, err := dlogProtocolCompiler.NewVerifier(r.sessionId, r.tape)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("cannot create dlog verifier")
	}
	err = dlogVerifier.Verify(dlogStatement, r1.Proof)
	if err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("verification failed")
	}

	r.state.omegaRaw = make([]uint64, r.suite.Xi()*r.suite.L())
	r.state.omega = make([]S, r.suite.Xi()*r.suite.L())
	r.state.rhoOmega = make([][]byte, r.suite.Xi()*r.suite.L())
	r.state.bigB = r1.BigB
	r.state.bigA = make([]P, r.suite.Xi()*r.suite.L())
	receiverOutput := &ReceiverOutput{
		ot.ReceiverOutput[[]byte]{
			Choices:  choices,
			Messages: make([][][]byte, r.suite.Xi()),
		},
	}
	for i := range r.suite.Xi() {
		c := uint64((choices[i/8] >> (i % 8)) & 0b1)
		receiverOutput.Messages[i] = make([][]byte, r.suite.L())
		for j := range r.suite.L() {
			idx := i*r.suite.L() + j
			a, err := r.suite.field.Random(r.prng)
			if err != nil {
				return nil, nil, errs2.Wrap(err).WithMessage("generating a")
			}
			r.state.omegaRaw[idx] = c
			r.state.omega[idx] = r.suite.field.FromUint64(r.state.omegaRaw[idx])
			r.state.bigA[idx] = r.suite.curve.ScalarBaseMul(a).Add(r.state.bigB.ScalarMul(r.state.omega[idx]))
			r.state.rhoOmega[idx], err = r.hash(idx, r.state.bigB, r.state.bigA[idx], r.state.bigB.ScalarMul(a).ToCompressed())
			if err != nil {
				return nil, nil, errs2.Wrap(err).WithMessage("cannot hash B * a_i")
			}
			receiverOutput.Messages[i][j] = r.state.rhoOmega[idx]

			r.tape.AppendBytes(fmt.Sprintf("%s%d-%d-", aLabel, i, j), r.state.bigA[idx].ToCompressed())
		}
	}

	r2 := &Round2P2P[P, B, S]{
		BigA: r.state.bigA,
	}
	r.round += 2
	return r2, receiverOutput, nil
}

// Round3 derives sender seeds rho0/rho1 and commits to them with digests and XOR masks.
func (s *Sender[P, B, S]) Round3(r2 *Round2P2P[P, B, S]) (*Round3P2P, *SenderOutput, error) {
	var err error
	if s.round != 3 {
		return nil, nil, ot.ErrRound.WithMessage("invalid round")
	}
	if err := r2.Validate(s.suite.Xi(), s.suite.L()); err != nil {
		return nil, nil, errs2.Wrap(err).WithMessage("invalid message")
	}

	rho0 := make([][]byte, s.suite.Xi()*s.suite.L())
	rho1 := make([][]byte, s.suite.Xi()*s.suite.L())
	s.state.rho0Digest = make([][]byte, s.suite.Xi()*s.suite.L())
	s.state.rho1Digest = make([][]byte, s.suite.Xi()*s.suite.L())
	s.state.rho0DigestDigest = make([][]byte, s.suite.Xi()*s.suite.L())
	xi := make([][]byte, s.suite.Xi()*s.suite.L())
	senderOutput := &SenderOutput{
		ot.SenderOutput[[]byte]{
			Messages: make([][2][][]byte, s.suite.Xi()),
		},
	}
	for i := range s.suite.Xi() {
		senderOutput.Messages[i][0] = make([][]byte, s.suite.L())
		senderOutput.Messages[i][1] = make([][]byte, s.suite.L())
		for j := range s.suite.L() {
			idx := i*s.suite.L() + j
			bigA := r2.BigA[idx]

			rho0[idx], err = s.hash(idx, s.state.bigB, bigA, bigA.ScalarMul(s.state.b).ToCompressed())
			if err != nil {
				return nil, nil, errs2.Wrap(err).WithMessage("cannot hash A * b_i")
			}
			rho1[idx], err = s.hash(idx, s.state.bigB, bigA, (bigA.Sub(s.state.bigB)).ScalarMul(s.state.b).ToCompressed())
			if err != nil {
				return nil, nil, errs2.Wrap(err).WithMessage("cannot hash (A - B_i) * b_i")
			}
			senderOutput.Messages[i][0][j] = rho0[idx]
			senderOutput.Messages[i][1][j] = rho1[idx]

			s.state.rho0Digest[idx], err = s.hash(idx, s.state.bigB, bigA, rho0[idx])
			if err != nil {
				return nil, nil, errs2.Wrap(err).WithMessage("cannot hash rho_0")
			}
			s.state.rho0DigestDigest[idx], err = s.hash(idx, s.state.bigB, bigA, s.state.rho0Digest[idx])
			if err != nil {
				return nil, nil, errs2.Wrap(err).WithMessage("cannot hash rho_0 digest")
			}
			s.state.rho1Digest[idx], err = s.hash(idx, s.state.bigB, bigA, rho1[idx])
			if err != nil {
				return nil, nil, errs2.Wrap(err).WithMessage("cannot hash rho_1")
			}
			rho1DigestDigest, err := s.hash(idx, s.state.bigB, bigA, s.state.rho1Digest[idx])
			if err != nil {
				return nil, nil, errs2.Wrap(err).WithMessage("cannot hash rho_1 digest")
			}
			xi[idx] = make([]byte, len(s.state.rho0DigestDigest[idx]))
			subtle.XORBytes(xi[idx], s.state.rho0DigestDigest[idx], rho1DigestDigest)

			s.tape.AppendBytes(fmt.Sprintf("%s%d-%d-", aLabel, i, j), bigA.ToCompressed())
		}
	}

	r3 := &Round3P2P{
		Xi: xi,
	}
	s.round += 2
	return r3, senderOutput, nil
}

// Round4 unblinds the masked digest corresponding to each receiver choice and returns rhoPrime values.
func (r *Receiver[P, B, S]) Round4(r3 *Round3P2P) (*Round4P2P, error) {
	var err error
	if r.round != 4 {
		return nil, ot.ErrRound.WithMessage("invalid round")
	}
	if err := r3.Validate(r.suite.Xi(), r.suite.L(), r.suite.hashFunc().Size()); err != nil {
		return nil, errs2.Wrap(err).WithMessage("invalid message")
	}

	r.state.xi = r3.Xi
	rhoPrime := make([][]byte, r.suite.Xi()*r.suite.L())
	r.state.rhoOmegaDigest = make([][]byte, r.suite.Xi()*r.suite.L())
	for i := range r.suite.Xi() {
		for j := range r.suite.L() {
			idx := i*r.suite.L() + j
			if len(r3.Xi[idx]) != r.suite.hashFunc().Size() {
				return nil, ot.ErrInvalidArgument.WithMessage("invalid message")
			}

			r.state.rhoOmegaDigest[idx], err = r.hash(idx, r.state.bigB, r.state.bigA[idx], r.state.rhoOmega[idx])
			if err != nil {
				return nil, errs2.Wrap(err).WithMessage("cannot hash rho_omega")
			}
			rhoPrime[idx], err = r.hash(idx, r.state.bigB, r.state.bigA[idx], r.state.rhoOmegaDigest[idx])
			if err != nil {
				return nil, errs2.Wrap(err).WithMessage("cannot hash rho_omega digest")
			}
			xi := ct.CSelectInts(ct.Choice(r.state.omegaRaw[idx]), make([]byte, len(r3.Xi[idx])), r3.Xi[idx])
			subtle.XORBytes(rhoPrime[idx], rhoPrime[idx], xi)
		}
	}

	r4 := &Round4P2P{
		RhoPrime: rhoPrime,
	}
	r.round += 2
	return r4, nil
}

// Round5 checks rhoPrime against sender commitments and returns digest openings.
func (s *Sender[P, B, S]) Round5(r4 *Round4P2P) (*Round5P2P, error) {
	if s.round != 5 {
		return nil, ot.ErrRound.WithMessage("invalid round")
	}
	if err := r4.Validate(s.suite.Xi(), s.suite.L(), s.suite.hashFunc().Size()); err != nil {
		return nil, errs2.Wrap(err).WithMessage("invalid message")
	}

	for i := range s.suite.Xi() {
		for j := range s.suite.L() {
			idx := i*s.suite.L() + j
			if len(r4.RhoPrime[idx]) != s.suite.hashFunc().Size() {
				return nil, ot.ErrInvalidArgument.WithMessage("invalid message")
			}

			if subtle.ConstantTimeCompare(r4.RhoPrime[idx], s.state.rho0DigestDigest[idx]) != 1 {
				return nil, errs2.ErrAbort.WithMessage("verification failed")
			}
		}
	}

	r5 := &Round5P2P{
		Rho0Digest: s.state.rho0Digest,
		Rho1Digest: s.state.rho1Digest,
	}
	s.round += 2
	return r5, nil
}

// Round6 verifies the sender's openings against the receiver's choice and internal hashes.
func (r *Receiver[P, B, S]) Round6(r5 *Round5P2P) error {
	if r.round != 6 {
		return ot.ErrRound.WithMessage("invalid round")
	}
	if err := r5.Validate(r.suite.Xi(), r.suite.L(), r.suite.hashFunc().Size()); err != nil {
		return errs2.Wrap(err).WithMessage("invalid message")
	}

	for i := range r.suite.Xi() {
		for j := range r.suite.L() {
			idx := i*r.suite.L() + j
			rho0Digest := r5.Rho0Digest[idx]
			rho1Digest := r5.Rho1Digest[idx]
			if len(rho0Digest) != r.suite.hashFunc().Size() || len(rho1Digest) != r.suite.hashFunc().Size() {
				return ot.ErrInvalidArgument.WithMessage("invalid message")
			}

			switch r.state.omegaRaw[idx] {
			case 0:
				if subtle.ConstantTimeCompare(rho0Digest, r.state.rhoOmegaDigest[idx]) != 1 {
					return errs2.ErrAbort.WithMessage("verification failed")
				}
			case 1:
				if subtle.ConstantTimeCompare(rho1Digest, r.state.rhoOmegaDigest[idx]) != 1 {
					return errs2.ErrAbort.WithMessage("verification failed")
				}
			default:
				panic("invalid internal state - this should never happen")
			}

			rho0DigestDigest, err := r.hash(idx, r.state.bigB, r.state.bigA[idx], rho0Digest)
			if err != nil {
				return errs2.Wrap(err).WithMessage("cannot hash rho_0 digest")
			}
			rho1DigestDigest, err := r.hash(idx, r.state.bigB, r.state.bigA[idx], rho1Digest)
			if err != nil {
				return errs2.Wrap(err).WithMessage("cannot hash rho_1 digest")
			}
			xi := make([]byte, len(rho0DigestDigest))
			subtle.XORBytes(xi, rho0DigestDigest, rho1DigestDigest)
			if subtle.ConstantTimeCompare(xi, r.state.xi[idx]) != 1 {
				return errs2.ErrAbort.WithMessage("verification failed")
			}
		}
	}

	return nil
}
