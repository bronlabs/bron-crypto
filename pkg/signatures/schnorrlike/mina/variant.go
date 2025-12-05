package mina

import (
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsig/tschnorr"
)

const VariantType schnorrlike.VariantType = "mina"

var (
	_ schnorrlike.Variant[*GroupElement, *Scalar, *Message]         = (*Variant)(nil)
	_ tschnorr.MPCFriendlyVariant[*GroupElement, *Scalar, *Message] = (*Variant)(nil)
)

func NewDeterministicVariant(nid NetworkId, privateKey *PrivateKey) (*Variant, error) {
	if privateKey == nil {
		return nil, errs.NewIsNil("private key is nil")
	}
	return &Variant{
		nid: nid,
		sk:  privateKey,
	}, nil
}

func NewRandomisedVariant(nid NetworkId, prng io.Reader) (*Variant, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	return &Variant{
		nid:  nid,
		prng: prng,
	}, nil
}

type Variant struct {
	nid  NetworkId
	sk   *PrivateKey
	prng io.Reader
}

func (*Variant) Type() schnorrlike.VariantType {
	return VariantType
}

func (*Variant) HashFunc() func() hash.Hash {
	return hashFunc
}

func (v *Variant) IsDeterministic() bool {
	return v.sk != nil
}

// https://github.com/o1-labs/o1js/blob/fdc94dd8d3735d01c232d7d7af49763e044b738b/src/mina-signer/src/signature.ts#L249
func (v *Variant) deriveNonceLegacy() (*Scalar, error) {
	pkx, err := v.sk.PublicKey().V.AffineX()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to get public key X coordinate")
	}
	pky, err := v.sk.PublicKey().V.AffineY()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to get public key Y coordinate")
	}

	// Get scalar and network ID in LE format
	scalarBytesLE := reversedBytes(v.sk.Value().Bytes())
	scalarBits := bytesToBits(scalarBytesLE)

	id, bitLength := getNetworkIdHashInput(v.nid)
	idBits := networkIdToBits(id, bitLength)

	// Use ROInput to properly structure the data
	input := new(ROInput).Init()
	input.AddFields(pkx, pky)
	input.AddBits(scalarBits...)
	input.AddBits(idBits...)

	// Pack to fields
	packed := input.PackToFields()

	// Convert packed fields to LE bytes for blake2b
	var allBytes []byte
	for _, field := range packed {
		fieldBytesLE := reversedBytes(field.Bytes())
		allBytes = append(allBytes, fieldBytesLE...)
	}

	digest := blake2b.Sum256(allBytes)

	// Blake2b digest as BE (interpret as-is)
	// Drop top two bits
	digest[0] &= 0x3f

	k, err := sf.FromBytes(digest[:])
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to create scalar from bytes")
	}
	return k, nil
}

func (v *Variant) ComputeNonceCommitment() (*GroupElement, *Scalar, error) {
	var k *Scalar
	var err error
	if v.IsDeterministic() {
		k, err = v.deriveNonceLegacy()
	} else {
		k, err = algebrautils.RandomNonIdentity(sf, v.prng)
	}
	if err != nil {
		return nil, nil, errs.WrapSerialisation(err, "failed to create scalar from bytes")
	}
	R := group.ScalarBaseMul(k)

	// Ensure R has an even y-coordinate (same as BIP340)
	ry, err := R.AffineY()
	if err != nil {
		return nil, nil, errs.WrapSerialisation(err, "cannot get y coordinate")
	}
	if ry.IsOdd() {
		// Negate k to flip the y-coordinate parity
		k = k.Neg()
		R = group.ScalarBaseMul(k)
	}

	return R, k, nil
}

// https://github.com/o1-labs/o1js/blob/885b50e60ead596cdcd8dc944df55fd3a4467a0a/src/mina-signer/src/signature.ts#L242
func (v *Variant) ComputeChallenge(nonceCommitment, publicKeyValue *GroupElement, message *Message) (*Scalar, error) {
	if nonceCommitment == nil || publicKeyValue == nil || message == nil {
		return nil, errs.NewIsNil("nonceCommitment, publicKeyValue and message must not be nil")
	}
	input := message.Clone()
	pkx, err := publicKeyValue.AffineX()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot get x")
	}
	pky, err := publicKeyValue.AffineY()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot get y")
	}
	ncx, err := nonceCommitment.AffineX()
	if err != nil {
		return nil, errs.WrapSerialisation(err, "cannot get x")
	}
	input.AddFields(pkx, pky, ncx)
	prefix := SignaturePrefix(v.nid)
	e, err := hashWithPrefix(prefix, input.PackToFields()...)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "failed to compute challenge")
	}
	return e, nil
}

func (v *Variant) ComputeResponse(privateKeyValue, nonce, challenge *Scalar) (*Scalar, error) {
	if privateKeyValue == nil || nonce == nil || challenge == nil {
		return nil, errs.NewIsNil("privateKeyValue, nonce and challenge must not be nil")
	}
	return nonce.Add(challenge.Mul(privateKeyValue)), nil
}

func (v *Variant) SerializeSignature(signature *Signature) ([]byte, error) {
	return SerializeSignature(signature)
}

// ============ MPC Methods ============.

func (v *Variant) CorrectAdditiveSecretShareParity(publicKey *PublicKey, share *additive.Share[*Scalar]) (*additive.Share[*Scalar], error) {
	// no changes needed
	return share, nil
}

func (v *Variant) CorrectPartialNonceParity(aggregatedNonceCommitments *GroupElement, localNonce *Scalar) (*GroupElement, *Scalar, error) {
	if aggregatedNonceCommitments == nil || localNonce == nil {
		return nil, nil, errs.NewIsNil("nonce commitment or k is nil")
	}
	correctedK := localNonce.Clone()
	ancy, err := aggregatedNonceCommitments.AffineY()
	if err != nil {
		return nil, nil, errs.WrapSerialisation(err, "cannot get y")
	}
	if ancy.IsOdd() {
		// If the nonce commitment is odd, we need to negate k to ensure that the parity is correct.
		correctedK = correctedK.Neg()
	}
	correctedR := group.ScalarBaseOp(correctedK)
	return correctedR, correctedK, nil
}
