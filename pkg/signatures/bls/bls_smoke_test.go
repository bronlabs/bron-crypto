package bls_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/bls"
)

func _[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
]() {
	var (
		_ signatures.KeyGenerator[*bls.PrivateKey[PK, PKFE, Sig, SigFE, E, S], *bls.PublicKey[PK, PKFE, Sig, SigFE, E, S]] = (*bls.KeyGenerator[PK, PKFE, Sig, SigFE, E, S])(nil)
		_ signatures.KeyGenerator[*bls.PrivateKey[Sig, SigFE, PK, PKFE, E, S], *bls.PublicKey[Sig, SigFE, PK, PKFE, E, S]] = (*bls.KeyGenerator[Sig, SigFE, PK, PKFE, E, S])(nil)

		_ signatures.BatchSigner[bls.Message, *bls.Signature[Sig, SigFE, PK, PKFE, E, S]]                                                 = (*bls.Signer[PK, PKFE, Sig, SigFE, E, S])(nil)
		_ signatures.BatchSigner[bls.Message, *bls.Signature[PK, PKFE, Sig, SigFE, E, S]]                                                 = (*bls.Signer[Sig, SigFE, PK, PKFE, E, S])(nil)
		_ signatures.AggregateSigner[bls.Message, *bls.Signature[Sig, SigFE, PK, PKFE, E, S], *bls.Signature[Sig, SigFE, PK, PKFE, E, S]] = (*bls.Signer[PK, PKFE, Sig, SigFE, E, S])(nil)
		_ signatures.AggregateSigner[bls.Message, *bls.Signature[PK, PKFE, Sig, SigFE, E, S], *bls.Signature[PK, PKFE, Sig, SigFE, E, S]] = (*bls.Signer[Sig, SigFE, PK, PKFE, E, S])(nil)

		_ signatures.Verifier[*bls.PublicKey[PK, PKFE, Sig, SigFE, E, S], bls.Message, *bls.Signature[Sig, SigFE, PK, PKFE, E, S]] = (*bls.Verifier[PK, PKFE, Sig, SigFE, E, S])(nil)
		_ signatures.Verifier[*bls.PublicKey[Sig, SigFE, PK, PKFE, E, S], bls.Message, *bls.Signature[PK, PKFE, Sig, SigFE, E, S]] = (*bls.Verifier[Sig, SigFE, PK, PKFE, E, S])(nil)

		_ signatures.AggregateVerifier[*bls.PublicKey[PK, PKFE, Sig, SigFE, E, S], bls.Message, *bls.Signature[Sig, SigFE, PK, PKFE, E, S], *bls.Signature[Sig, SigFE, PK, PKFE, E, S]] = (*bls.Verifier[PK, PKFE, Sig, SigFE, E, S])(nil)
		_ signatures.AggregateVerifier[*bls.PublicKey[Sig, SigFE, PK, PKFE, E, S], bls.Message, *bls.Signature[PK, PKFE, Sig, SigFE, E, S], *bls.Signature[PK, PKFE, Sig, SigFE, E, S]] = (*bls.Verifier[Sig, SigFE, PK, PKFE, E, S])(nil)

		// _ signatures.BatchVerifier[*bls.PublicKey[PK, PKFE, Sig, SigFE, E, S], bls.Message, *bls.Signature[Sig, SigFE, PK, PKFE, E, S]] = (*bls.Verifier[PK, PKFE, Sig, SigFE, E, S])(nil)
		// _ signatures.BatchVerifier[*bls.PublicKey[Sig, SigFE, PK, PKFE, E, S], bls.Message, *bls.Signature[PK, PKFE, Sig, SigFE, E, S]] = (*bls.Verifier[Sig, SigFE, PK, PKFE, E, S])(nil)

		// _ signatures.BatchAggregateVerifier[*bls.PublicKey[PK, PKFE, Sig, SigFE, E, S], bls.Message, *bls.Signature[Sig, SigFE, PK, PKFE, E, S], *bls.Signature[Sig, SigFE, PK, PKFE, E, S]] = (*bls.Verifier[PK, PKFE, Sig, SigFE, E, S])(nil)
		// _ signatures.BatchAggregateVerifier[*bls.PublicKey[Sig, SigFE, PK, PKFE, E, S], bls.Message, *bls.Signature[PK, PKFE, Sig, SigFE, E, S], *bls.Signature[PK, PKFE, Sig, SigFE, E, S]] = (*bls.Verifier[Sig, SigFE, PK, PKFE, E, S])(nil)
	)
}

func _[
	PK curves.PairingFriendlyPoint[PK, PKFE, Sig, SigFE, E, S], PKFE algebra.FieldElement[PKFE],
	Sig curves.PairingFriendlyPoint[Sig, SigFE, PK, PKFE, E, S], SigFE algebra.FieldElement[SigFE],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
]() {
	var (
		_ signatures.AggregatablePublicKey[*bls.PublicKey[PK, PKFE, Sig, SigFE, E, S]]                      = (*bls.PublicKey[PK, PKFE, Sig, SigFE, E, S])(nil)
		_ signatures.PrivateKey[*bls.PrivateKey[PK, PKFE, Sig, SigFE, E, S]]                                = (*bls.PrivateKey[PK, PKFE, Sig, SigFE, E, S])(nil)
		_ signatures.IncrementallyAggregatableSignature[*bls.Signature[PK, PKFE, Sig, SigFE, E, S]]         = (*bls.Signature[PK, PKFE, Sig, SigFE, E, S])(nil)
		_ signatures.IncrementallyAggregatableSignature[*bls.ProofOfPossession[PK, PKFE, Sig, SigFE, E, S]] = (*bls.ProofOfPossession[PK, PKFE, Sig, SigFE, E, S])(nil)
	)
}

func _[
	P1 curves.PairingFriendlyPoint[P1, FE1, P2, FE2, E, S], FE1 algebra.FieldElement[FE1],
	P2 curves.PairingFriendlyPoint[P2, FE2, P1, FE1, E, S], FE2 algebra.FieldElement[FE2],
	E algebra.MultiplicativeGroupElement[E], S algebra.PrimeFieldElement[S],
]() {
	var (
		_ signatures.Scheme[
			*bls.PrivateKey[P1, FE1, P2, FE2, E, S], *bls.PublicKey[P1, FE1, P2, FE2, E, S],
			[]byte, *bls.Signature[P2, FE2, P1, FE1, E, S],
			*bls.KeyGenerator[P1, FE1, P2, FE2, E, S], *bls.Signer[P1, FE1, P2, FE2, E, S], *bls.Verifier[P1, FE1, P2, FE2, E, S],
		] = (*bls.Scheme[P1, FE1, P2, FE2, E, S])(nil)

		_ signatures.Scheme[
			*bls.PrivateKey[P2, FE2, P1, FE1, E, S], *bls.PublicKey[P2, FE2, P1, FE1, E, S],
			[]byte, *bls.Signature[P1, FE1, P2, FE2, E, S],
			*bls.KeyGenerator[P2, FE2, P1, FE1, E, S], *bls.Signer[P2, FE2, P1, FE1, E, S], *bls.Verifier[P2, FE2, P1, FE1, E, S],
		] = (*bls.Scheme[P2, FE2, P1, FE1, E, S])(nil)

		_ signatures.AggregatableScheme[
			*bls.PrivateKey[P1, FE1, P2, FE2, E, S], *bls.PublicKey[P1, FE1, P2, FE2, E, S],
			[]byte, *bls.Signature[P2, FE2, P1, FE1, E, S],
			*bls.KeyGenerator[P1, FE1, P2, FE2, E, S], *bls.Signer[P1, FE1, P2, FE2, E, S], *bls.Verifier[P1, FE1, P2, FE2, E, S],
			*bls.Signature[P2, FE2, P1, FE1, E, S],
		] = (*bls.Scheme[P1, FE1, P2, FE2, E, S])(nil)

		_ signatures.AggregatableScheme[
			*bls.PrivateKey[P2, FE2, P1, FE1, E, S], *bls.PublicKey[P2, FE2, P1, FE1, E, S],
			[]byte, *bls.Signature[P1, FE1, P2, FE2, E, S],
			*bls.KeyGenerator[P2, FE2, P1, FE1, E, S], *bls.Signer[P2, FE2, P1, FE1, E, S], *bls.Verifier[P2, FE2, P1, FE1, E, S],
			*bls.Signature[P1, FE1, P2, FE2, E, S],
		] = (*bls.Scheme[P2, FE2, P1, FE1, E, S])(nil)
	)
}
