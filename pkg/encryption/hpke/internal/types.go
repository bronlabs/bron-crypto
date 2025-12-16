package internal

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"math"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/key_agreement/dh/dhc"
)

const version = "HPKE-v1"

type (
	PrivateKey[S algebra.PrimeFieldElement[S]] struct {
		dhc.ExtendedPrivateKey[S]
	}
	PublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
		dhc.PublicKey[P, B, S]
	}
)

func (sk *PrivateKey[S]) Bytes() []byte {
	out, err := dhc.SerialiseExtendedPrivateKey(&sk.ExtendedPrivateKey)
	if err != nil {
		panic(errs2.Wrap(err))
	}
	return out
}

func (pk *PublicKey[P, B, S]) Bytes() []byte {
	out, err := dhc.SerialisePublicKey(&pk.PublicKey)
	if err != nil {
		panic(errs2.Wrap(err))
	}
	return out
}

func (pk *PublicKey[P, B, S]) Clone() *PublicKey[P, B, S] {
	return &PublicKey[P, B, S]{PublicKey: *pk.PublicKey.Clone()}
}

func (pk *PublicKey[P, B, S]) Equal(other *PublicKey[P, B, S]) bool {
	if pk == nil || other == nil {
		return pk == other
	}
	return pk.PublicKey.Equal(&other.PublicKey)
}

func NewPrivateKey[S algebra.PrimeFieldElement[S]](sf algebra.PrimeField[S], ikm []byte) (*PrivateKey[S], error) {
	seed, err := dhc.NewPrivateKey(ikm)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	sk, err := dhc.ExtendPrivateKey(seed, sf)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return &PrivateKey[S]{ExtendedPrivateKey: *sk}, nil
}

func NewPublicKey[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](v P) (*PublicKey[P, B, S], error) {
	out, err := dhc.NewPublicKey(v)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	return &PublicKey[P, B, S]{PublicKey: *out}, nil
}

type ModeID byte

const (
	Base    ModeID = 0x00
	PSk     ModeID = 0x01
	Auth    ModeID = 0x02
	AuthPSk ModeID = 0x03
)

type ContextRole byte

const (
	SenderRole ContextRole = iota
	ReceiverRole
)

func NewCipherSuite(kem KEMID, kdf KDFID, aead AEADID) (*CipherSuite, error) {
	if kem == DHKEM_RESERVED {
		return nil, ErrNotSupported.WithMessage("invalid KEM ID").WithStackFrame()
	}
	if kdf == KDF_HKDF_RESERVED {
		return nil, ErrNotSupported.WithMessage("invalid KDF ID").WithStackFrame()
	}
	if aead == AEAD_RESERVED {
		return nil, ErrNotSupported.WithMessage("invalid AEAD ID").WithStackFrame()
	}
	return &CipherSuite{
		kem:  kem,
		kdf:  kdf,
		aead: aead,
	}, nil
}

type CipherSuite struct {
	kdf  KDFID
	kem  KEMID
	aead AEADID
}

func (c *CipherSuite) KDFID() KDFID {
	return c.kdf
}

func (c *CipherSuite) KEMID() KEMID {
	return c.kem
}

func (c *CipherSuite) AEADID() AEADID {
	return c.aead
}

func (c *CipherSuite) ID() []byte {
	suiteID := make([]byte, 6)
	binary.BigEndian.PutUint16(suiteID, uint16(c.kem))
	binary.BigEndian.PutUint16(suiteID[2:], uint16(c.kdf))
	binary.BigEndian.PutUint16(suiteID[4:], uint16(c.aead))
	return append([]byte("HPKE"), suiteID...)
}

// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1-13
type KeyScheduleContext struct {
	Mode      ModeID
	PskIdHash []byte // size Nh
	InfoHash  []byte // size Nh
}

func (ksc *KeyScheduleContext) Marshal() []byte {
	return slices.Concat([]byte{byte(ksc.Mode)}, ksc.PskIdHash, ksc.InfoHash)
}

type context struct {
	role           ContextRole
	suite          *CipherSuite
	key            []byte
	exporterSecret []byte

	baseNonce nonce
	sequence  uint64

	aead          cipher.AEAD
	nonces        ds.MutableSet[nonce]
	keyScheduling *KeyScheduleContext
	secret        []byte
}

var _ base.Hashable[nonce] = (*nonce)(nil)

type nonce []byte

func (n nonce) Equal(other nonce) bool {
	return subtle.ConstantTimeCompare(n, other) == 1
}

func (n nonce) HashCode() base.HashCode {
	return base.DeriveHashCode(n)
}

// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2-12
func (c *context) computeNonce() ([]byte, error) {
	Nn := aeads[c.suite.aead].Nn()
	buf := make([]byte, 8) // because sequence is uint64
	binary.BigEndian.PutUint64(buf, c.sequence)
	newNonce := make(nonce, Nn)
	copy(newNonce, c.baseNonce)
	// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2-6
	subtle.XORBytes(newNonce[Nn-8:], c.baseNonce[Nn-8:], buf) // length of sequence (uint64) is smaller than Nn. So we treat as zero-padded.
	if c.nonces.Contains(newNonce) {
		return nil, ErrInvalidNonce.WithMessage("nonce reuse detected").WithStackFrame()
	}
	c.nonces.Add(newNonce)
	return newNonce, nil
}

func (c *context) incrementSeq() error {
	// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2-6
	// Implementations MAY use a sequence number that is shorter than the nonce length (padding on the left with zero), but MUST raise an error if the sequence number overflows.
	// The default check of the rfc ((1<<(8*Nn))-1) is larger than uint64, so no point in copying the rfc.
	if c.sequence == math.MaxUint64 {
		return ErrInvalidNonce.WithMessage("sequence number will overflow").WithStackFrame()
	}
	c.sequence++
	return nil
}

// export takes as input a context string exporter_context and a desired length L in bytes, and produces a secret derived from the internal exporter secret using the corresponding KDF Expand function. This is an interface for exporting secrets from the encryption context using a variable-length pseudorandom function (PRF), similar to the TLS 1.3 exporter interface
// https://www.rfc-editor.org/rfc/rfc9180.html#name-secret-export
func (c *context) export(exporterContext []byte, L int) ([]byte, error) {
	kdf := kdfs[c.suite.kdf]
	if L > 255*kdf.Nh() {
		return nil, ErrInvalidArgument.WithMessage("L is out of range").WithStackFrame()
	}
	return kdf.labeledExpand(c.suite.ID(), c.exporterSecret, []byte("sec"), exporterContext, L), nil
}

// keySchedule translates the protocol inputs into an encryption context.
// - mode: A one-byte value indicating the HPKE mode, defined in Table 1.
// - shared_secret: A KEM shared secret generated for this transaction.
// - info: Application-supplied information (optional; default value "").
// - psk A pre-shared key (PSK) held by both the sender and the recipient (optional; default value "").
// - psk_id: An identifier for the PSK (optional; default value "").
// https://www.rfc-editor.org/rfc/rfc9180.html#name-creating-the-encryption-con
func keySchedule(role ContextRole, cipherSuite *CipherSuite, mode ModeID, sharedSecret, info, psk, pskId []byte) (*context, *KeyScheduleContext, error) {
	if err := verifyPSKInputs(mode, psk, pskId); err != nil {
		return nil, nil, errs2.Wrap(err)
	}

	var err error
	kdf := kdfs[cipherSuite.kdf]
	aead := aeads[cipherSuite.aead]
	pskIdHash := kdf.labeledExtract(cipherSuite.ID(), nil, []byte("psk_id_hash"), pskId)
	infoHash := kdf.labeledExtract(cipherSuite.ID(), nil, []byte("info_hash"), info)
	keyScheduleContext := &KeyScheduleContext{
		Mode:      mode,
		PskIdHash: pskIdHash,
		InfoHash:  infoHash,
	}
	keyScheduleContextMarshaled := keyScheduleContext.Marshal()
	secret := kdf.labeledExtract(cipherSuite.ID(), sharedSecret, []byte("secret"), psk)

	ctx := &context{
		role:  role,
		suite: cipherSuite,

		keyScheduling:  keyScheduleContext,
		secret:         secret,
		exporterSecret: kdf.labeledExpand(cipherSuite.ID(), secret, []byte("exp"), keyScheduleContextMarshaled, kdf.Nh()),
		nonces:         hashset.NewHashable[nonce](),
	}

	// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.3-4
	if cipherSuite.aead != AEAD_EXPORT_ONLY {
		ctx.key = kdf.labeledExpand(cipherSuite.ID(), secret, []byte("key"), keyScheduleContextMarshaled, aead.Nk())
		ctx.baseNonce = kdf.labeledExpand(cipherSuite.ID(), secret, []byte("base_nonce"), keyScheduleContextMarshaled, aead.Nn())

		ctx.aead, err = aead.New(ctx.key)
		if err != nil {
			return nil, nil, errs2.Wrap(err)
		}
	}

	return ctx, keyScheduleContext, nil
}

// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1-10
func verifyPSKInputs(mode ModeID, psk, pskId []byte) error {
	gotPsk := psk != nil
	gotPskId := pskId != nil
	if gotPsk != gotPskId {
		return ErrInvalidArgument.WithMessage("either psk and pskId should both be nil, or none should be nil").WithStackFrame()
	}
	if gotPsk && (mode == Base || mode == Auth) {
		return ErrInvalidArgument.WithMessage("psk argument provided when not needed").WithStackFrame()
	}
	if !gotPsk && (mode == PSk || mode == AuthPSk) {
		return ErrInvalidArgument.WithMessage("missing required psk input").WithStackFrame()
	}
	return nil
}

type SenderContext[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	Capsule *PublicKey[P, B, S]
	ctx     *context
}

func NewSenderContext[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](mode ModeID, suite *CipherSuite, receiverPublicKey *PublicKey[P, B, S], senderPrivateKey *PrivateKey[S], info, psk, pskId []byte, prng io.Reader) (*SenderContext[P, B, S], error) {
	if suite == nil {
		return nil, ErrInvalidArgument.WithMessage("ciphersuite is nil").WithStackFrame()
	}

	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](receiverPublicKey.Value().Structure())
	kdf, err := NewKDF(suite.kdf)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	kem, err := NewDHKEM(curve, kdf)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	var sharedSecret []byte
	var ephemeralPublicKey *PublicKey[P, B, S]
	if mode == Auth || mode == AuthPSk {
		sharedSecret, ephemeralPublicKey, err = kem.AuthEncap(receiverPublicKey, senderPrivateKey, prng)
	} else {
		if senderPrivateKey != nil {
			return nil, ErrNotSupported.WithMessage("sender private key unsupported").WithStackFrame()
		}

		sharedSecret, ephemeralPublicKey, err = kem.Encap(receiverPublicKey, prng)
	}
	if err != nil {
		return nil, errs2.Wrap(err)
	}

	ctx, _, err := keySchedule(SenderRole, suite, mode, sharedSecret, info, psk, pskId)
	if err != nil {
		return nil, errs2.Wrap(err)
	}

	return &SenderContext[P, B, S]{
		Capsule: ephemeralPublicKey,
		ctx:     ctx,
	}, nil
}

func (s *SenderContext[P, B, S]) Seal(plaintext, additionalData []byte) (ciphertext []byte, err error) {
	nonce, err := s.ctx.computeNonce()
	if err != nil {
		return nil, errs2.Wrap(err)
	}

	ciphertext = s.ctx.aead.Seal(nil, nonce, plaintext, additionalData)
	if err := s.ctx.incrementSeq(); err != nil {
		return nil, errs2.Wrap(err)
	}

	return ciphertext, nil
}

// Export takes as input a context string exporter_context and a desired length L in bytes, and produces a secret derived from the internal exporter secret using the corresponding KDF Expand function. This is an interface for exporting secrets from the encryption context using a variable-length pseudorandom function (PRF), similar to the TLS 1.3 exporter interface
// https://www.rfc-editor.org/rfc/rfc9180.html#name-secret-export
func (s *SenderContext[P, B, S]) Export(exporterContext []byte, L int) ([]byte, error) {
	return s.ctx.export(exporterContext, L)
}

type ReceiverContext[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]] struct {
	ctx     *context
	capsule *PublicKey[P, B, S]
}

func NewReceiverContext[P curves.Point[P, B, S], B algebra.FiniteFieldElement[B], S algebra.PrimeFieldElement[S]](mode ModeID, suite *CipherSuite, receiverPrivatekey *PrivateKey[S], ephemeralPublicKey, senderPublicKey *PublicKey[P, B, S], info, psk, pskId []byte) (*ReceiverContext[P, B, S], error) {
	if suite == nil {
		return nil, ErrInvalidArgument.WithMessage("ciphersuite is nil").WithStackFrame()
	}

	curve := algebra.StructureMustBeAs[curves.Curve[P, B, S]](ephemeralPublicKey.Value().Structure())
	kdf, err := NewKDF(suite.kdf)
	if err != nil {
		return nil, errs2.Wrap(err)
	}
	kem, err := NewDHKEM(curve, kdf)
	if err != nil {
		return nil, errs2.Wrap(err)
	}

	var sharedSecret []byte
	if mode == Auth || mode == AuthPSk {
		sharedSecret, err = kem.AuthDecap(receiverPrivatekey, senderPublicKey, ephemeralPublicKey)
	} else {
		if senderPublicKey != nil {
			return nil, ErrNotSupported.WithMessage("sender public key unsupported").WithStackFrame()
		}

		sharedSecret, err = kem.Decap(receiverPrivatekey, ephemeralPublicKey)
	}
	if err != nil {
		return nil, errs2.Wrap(err)
	}

	ctx, _, err := keySchedule(ReceiverRole, suite, mode, sharedSecret, info, psk, pskId)
	if err != nil {
		return nil, errs2.Wrap(err)
	}

	return &ReceiverContext[P, B, S]{
		ctx:     ctx,
		capsule: ephemeralPublicKey,
	}, nil
}

func (r *ReceiverContext[P, B, S]) Open(ciphertext, additionalData []byte) (plaintext []byte, err error) {
	nonce, err := r.ctx.computeNonce()
	if err != nil {
		return nil, errs2.Wrap(err)
	}

	plaintext, err = r.ctx.aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, errs2.Wrap(err)
	}

	if err := r.ctx.incrementSeq(); err != nil {
		return nil, errs2.Wrap(err)
	}

	return plaintext, nil
}

// Export takes as input a context string exporter_context and a desired length L in bytes, and produces a secret derived from the internal exporter secret using the corresponding KDF Expand function. This is an interface for exporting secrets from the encryption context using a variable-length pseudorandom function (PRF), similar to the TLS 1.3 exporter interface
// https://www.rfc-editor.org/rfc/rfc9180.html#name-secret-export
func (r *ReceiverContext[P, B, S]) Export(exporterContext []byte, L int) ([]byte, error) {
	return r.ctx.export(exporterContext, L)
}

func (r *ReceiverContext[P, B, S]) Capsule() *PublicKey[P, B, S] {
	return r.capsule
}
