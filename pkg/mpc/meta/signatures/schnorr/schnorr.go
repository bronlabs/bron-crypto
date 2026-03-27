package schnorr

import (
	"sync"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/mpc"
	mpcsig "github.com/bronlabs/bron-crypto/pkg/mpc/meta/signatures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw/msp"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/vss/meta/feldman"
	"github.com/bronlabs/bron-crypto/pkg/signatures"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
)

// MPCFriendlyVariant extends schnorrlike.Variant with methods needed for threshold signing.
// It provides parity correction for secret shares and nonces required by some Schnorr variants.
type MPCFriendlyVariant[GE algebra.PrimeGroupElement[GE, S], S algebra.PrimeFieldElement[S], M schnorrlike.Message] interface {
	schnorrlike.Variant[GE, S, M]
	CorrectAdditiveSecretShareParity(publicKey *schnorrlike.PublicKey[GE, S], share *additive.Share[S]) (*additive.Share[S], error)
	CorrectPartialNonceParity(aggregatedNonceCommitment GE, nonce S) (GE, S, error)
}

// MPCFriendlyScheme extends schnorrlike.Scheme with threshold signing capabilities.
// It provides a partial signature verifier for validating individual party contributions.
type MPCFriendlyScheme[
	VR MPCFriendlyVariant[GE, S, M],
	GE algebra.PrimeGroupElement[GE, S],
	S algebra.PrimeFieldElement[S],
	M schnorrlike.Message,
	KG signatures.KeyGenerator[*schnorrlike.PrivateKey[GE, S], *schnorrlike.PublicKey[GE, S]],
	SG schnorrlike.Signer[VR, GE, S, M],
	VF schnorrlike.Verifier[VR, GE, S, M],
] interface {
	schnorrlike.Scheme[VR, GE, S, M, KG, SG, VF]
	PartialSignatureVerifier(
		fullPublicKey *schnorrlike.PublicKey[GE, S],
		opts ...signatures.VerifierOption[VF, *schnorrlike.PublicKey[GE, S], M, *schnorrlike.Signature[GE, S]],
	) (schnorrlike.Verifier[VR, GE, S, M], error) // making batch verification etc is not objective here, so won't return VF
}

// PartialSignature represents a party's contribution to a threshold Schnorr signature.
type PartialSignature[
	GE algebra.PrimeGroupElement[GE, S],
	S algebra.PrimeFieldElement[S],
] struct {
	Sig schnorrlike.Signature[GE, S] `cbor:"signature"`
}

// Bytes serialises the partial signature to a byte slice.
func (ps *PartialSignature[E, S]) Bytes() []byte {
	if ps == nil {
		return nil
	}
	out := ps.Sig.S.Bytes()
	out = append(out, ps.Sig.R.Bytes()...)
	out = append(out, ps.Sig.E.Bytes()...)
	return out
}

// PublicMaterial contains public information for threshold Schnorr signature verification.
type PublicMaterial[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]] struct {
	mpc.BasePublicMaterial[E, S]

	pk     *schnorrlike.PublicKey[E, S]
	pkOnce sync.Once
}

// PublicKey returns the threshold public key as a schnorrlike.PublicKey.
func (pm *PublicMaterial[E, S]) PublicKey() *schnorrlike.PublicKey[E, S] {
	pm.pkOnce.Do(func() {
		var err error
		pm.pk, err = schnorrlike.NewPublicKey(pm.PublicKeyValue())
		if err != nil {
			panic(err)
		}
	})
	return pm.pk
}

// Shard represents a party's secret key share for threshold Schnorr signing.
type Shard[
	E algebra.PrimeGroupElement[E, S],
	S algebra.PrimeFieldElement[S],
] struct {
	mpc.BaseShard[E, S]

	pk     *schnorrlike.PublicKey[E, S]
	pkOnce sync.Once
}

// PublicKeyMaterial returns the public material derived from this shard.
func (sh *Shard[E, S]) PublicKeyMaterial() *PublicMaterial[E, S] {
	return &PublicMaterial[E, S]{
		BasePublicMaterial: sh.BasePublicMaterial,
		pk:                 sh.pk,
		pkOnce:             sync.Once{},
	}
}

// PublicKey returns the threshold public key as a schnorrlike.PublicKey.
func (sh *Shard[E, S]) PublicKey() *schnorrlike.PublicKey[E, S] {
	sh.pkOnce.Do(func() {
		var err error
		sh.pk, err = schnorrlike.NewPublicKey(sh.PublicKeyValue())
		if err != nil {
			panic(err)
		}
	})
	return sh.pk
}

// Equal returns true if this shard equals another shard.
func (sh *Shard[E, S]) Equal(other mpcsig.Shard[*schnorrlike.PublicKey[E, S], *feldman.Share[S]]) bool {
	o, ok := other.(*Shard[E, S])
	return ok && sh.BaseShard.Equal(&o.BaseShard)
}

// NewShard creates a new threshold Schnorr shard from a Feldman share, verification vector, and access structure.
func NewShard[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	share *feldman.Share[S],
	fv *feldman.VerificationVector[E, S],
	mspMatrix *msp.MSP[S],
) (*Shard[E, S], error) {
	bs, err := mpc.NewBaseShard(share, fv, mspMatrix)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create base shard")
	}
	df, err := feldman.NewLiftedDealerFunc(fv, mspMatrix)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create lifted dealer function")
	}
	pk, err := schnorrlike.NewPublicKey(df.LiftedSecret().Value())
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("could not create public key from verification vector")
	}
	return &Shard[E, S]{BaseShard: *bs, pk: pk, pkOnce: sync.Once{}}, nil
}

var (
	// ErrInvalidArgument is returned when an input is invalid or inconsistent.
	ErrInvalidArgument = errs.New("invalid argument")
)
