package signatures

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

type Name string

type (
	PrivateKey[SK any] base.Equatable[SK]
	PublicKey[PK any]  interface {
		base.Clonable[PK]
		base.Hashable[PK]
	}
	AggregatablePublicKey[PK any] interface {
		PublicKey[PK]
		algebra.MaybeSummand[PK]
	}

	Message          any
	Signature[S any] interface {
		base.Clonable[S]
		base.Hashable[S]
	}

	IncrementallyAggregatableSignature[S any] interface {
		Signature[S]
		algebra.MaybeSummand[S]
	}
)

type (
	KeyGenerator[SK PrivateKey[SK], PK PublicKey[PK]] interface {
		Generate(prng io.Reader) (SK, PK, error)
	}

	ExtendedKeyGenerator[SK PrivateKey[SK], PK PublicKey[PK]] interface {
		KeyGenerator[SK, PK]
		GenerateWithSeed(ikm []byte) (SK, PK, error)
	}

	KeyGeneratorOption[
		KG KeyGenerator[SK, PK], SK PrivateKey[SK], PK PublicKey[PK],
	] = func(KG) error
)

type (
	Signer[M Message, S Signature[S]] interface {
		Sign(message M) (S, error)
	}

	BatchSigner[M Message, S Signature[S]] interface {
		Signer[M, S]
		BatchSign(...M) ([]S, error)
	}
	AggregateSigner[M Message, S Signature[S], AG Signature[AG]] interface {
		Signer[M, S]
		AggregateSign(messages ...M) (AG, error)
	}

	SignerOption[
		SG Signer[M, S], M Message, S Signature[S],
	] = func(SG) error
)

type (
	Verifier[PK PublicKey[PK], M Message, S Signature[S]] interface {
		Verify(S, PK, M) error
	}

	AggregateVerifier[PK PublicKey[PK], M Message, S Signature[S], AG Signature[AG]] interface {
		Verifier[PK, M, S]
		AggregateVerify(AG, []PK, []M) error
	}

	BatchVerifier[PK PublicKey[PK], M Message, S Signature[S]] interface {
		Verifier[PK, M, S]
		BatchVerify([]S, []PK, []M) error
	}

	BatchAggregateVerifier[PK PublicKey[PK], M Message, S Signature[S], AG Signature[AG]] interface {
		Verifier[PK, M, S]
		BatchAggregateVerify([]AG, []PK, [][]M) error
	}

	VerifierOption[
		VF Verifier[PK, M, S], PK PublicKey[PK], M Message, S Signature[S],
	] = func(VF) error
)

type (
	Scheme[
		SK PrivateKey[SK], PK PublicKey[PK], M Message, S Signature[S],
		KG KeyGenerator[SK, PK], SG Signer[M, S], VF Verifier[PK, M, S],
	] interface {
		Name() Name
		Keygen(...KeyGeneratorOption[KG, SK, PK]) (KG, error)
		Signer(SK, ...SignerOption[SG, M, S]) (SG, error)
		Verifier(...VerifierOption[VF, PK, M, S]) (VF, error)
	}
	AggregatableScheme[
		SK PrivateKey[SK], PK AggregatablePublicKey[PK], M Message, S Signature[S],
		KG KeyGenerator[SK, PK], SG Signer[M, S], VF AggregateVerifier[PK, M, S, AG], AG Signature[AG],
	] interface {
		Scheme[SK, PK, M, S, KG, SG, VF]
		AggregateSignatures(...S) (AG, error)
	}

	BatchableScheme[
		SK PrivateKey[SK], PK PublicKey[PK], M Message, S Signature[S],
		KG KeyGenerator[SK, PK], SG BatchSigner[M, S], VF BatchVerifier[PK, M, S],
	] Scheme[SK, PK, M, S, KG, SG, VF]
)
