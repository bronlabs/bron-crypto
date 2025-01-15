package hpke

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"math"
	"slices"

	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

const version = "HPKE-v1"

type PrivateKey struct {
	D curves.Scalar
	PublicKey

	_ ds.Incomparable
}

type PublicKey = curves.Point

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

type CipherSuite struct {
	KDF  KDFID
	KEM  KEMID
	AEAD AEADID
}

func (c *CipherSuite) ID() []byte {
	suiteID := make([]byte, 6)
	binary.BigEndian.PutUint16(suiteID, uint16(c.KEM))
	binary.BigEndian.PutUint16(suiteID[2:], uint16(c.KDF))
	binary.BigEndian.PutUint16(suiteID[4:], uint16(c.AEAD))
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
	nonces        ds.Set[nonce]
	keyScheduling *KeyScheduleContext
	secret        []byte

	_ ds.Incomparable
}

var _ ds.Hashable[nonce] = (*nonce)(nil)

type nonce []byte

func (n nonce) Equal(other nonce) bool {
	return subtle.ConstantTimeCompare(n, other) == 1
}

func (n nonce) HashCode() uint64 {
	return binary.BigEndian.Uint64(bitstring.PadToRight(n, 8-len(n)))
}

// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2-12
func (c *context) computeNonce() ([]byte, error) {
	Nn := aeads[c.suite.AEAD].Nn()
	buf := make([]byte, 8) // because sequence is uint64
	binary.BigEndian.PutUint64(buf, c.sequence)
	newNonce := make(nonce, Nn)
	copy(newNonce, c.baseNonce)
	// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2-6
	subtle.XORBytes(newNonce[Nn-8:], c.baseNonce[Nn-8:], buf) // length of sequence (uint64) is smaller than Nn. So we treat as zero-padded.
	if c.nonces.Contains(newNonce) {
		return nil, errs.NewMembership("computed nonce is used before")
	}
	c.nonces.Add(newNonce)
	return newNonce, nil
}

func (c *context) incrementSeq() error {
	// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.2-6
	// Implementations MAY use a sequence number that is shorter than the nonce length (padding on the left with zero), but MUST raise an error if the sequence number overflows.
	// The default check of the rfc ((1<<(8*Nn))-1) is larger than uint64, so no point in copying the rfc.
	if c.sequence == math.MaxUint64 {
		return errs.NewFailed("sequence number will overflow")
	}
	c.sequence++
	return nil
}

// export takes as input a context string exporter_context and a desired length L in bytes, and produces a secret derived from the internal exporter secret using the corresponding KDF Expand function. This is an interface for exporting secrets from the encryption context using a variable-length pseudorandom function (PRF), similar to the TLS 1.3 exporter interface
// https://www.rfc-editor.org/rfc/rfc9180.html#name-secret-export
func (c *context) export(exporterContext []byte, L int) ([]byte, error) {
	kdf := kdfs[c.suite.KDF]
	if L > 255*kdf.Nh() {
		return nil, errs.NewValue("L is out of range")
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
		return nil, nil, errs.WrapArgument(err, "psk arguments are invalid")
	}

	var err error
	kdf := kdfs[cipherSuite.KDF]
	aead := aeads[cipherSuite.AEAD]
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
		nonces:         hashset.NewHashableHashSet[nonce](),
	}

	// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.3-4
	if cipherSuite.AEAD != AEAD_EXPORT_ONLY {
		ctx.key = kdf.labeledExpand(cipherSuite.ID(), secret, []byte("key"), keyScheduleContextMarshaled, aead.Nk())
		ctx.baseNonce = kdf.labeledExpand(cipherSuite.ID(), secret, []byte("base_nonce"), keyScheduleContextMarshaled, aead.Nn())

		ctx.aead, err = aead.New(ctx.key)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not create aead cipher")
		}
	}

	return ctx, keyScheduleContext, nil
}

// https://www.rfc-editor.org/rfc/rfc9180.html#section-5.1-10
func verifyPSKInputs(mode ModeID, psk, pskId []byte) error {
	gotPsk := psk != nil
	gotPskId := pskId != nil
	if gotPsk != gotPskId {
		return errs.NewArgument("either psk and pskId should both be nil, or none should be nil")
	}
	if gotPsk && (mode == Base || mode == Auth) {
		return errs.NewArgument("psk argument provided when not needed")
	}
	if !gotPsk && (mode == PSk || mode == AuthPSk) {
		return errs.NewArgument("mssing required psk input")
	}
	return nil
}
