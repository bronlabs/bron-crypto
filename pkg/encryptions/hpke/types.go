package hpke

import (
	"bytes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"

	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/errs"
)

const version = "HPKE-v1"

type PrivateKey struct {
	D curves.Scalar
	PublicKey
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
	return bytes.Join([][]byte{{byte(ksc.Mode)}, ksc.PskIdHash, ksc.InfoHash}, nil)
}

type context struct {
	role           ContextRole
	suite          *CipherSuite
	key            []byte
	exporterSecret []byte

	baseNonce []byte
	sequence  uint64

	aead cipher.AEAD
	// TODO: use hashset
	nonces        [][]byte
	keyScheduling *KeyScheduleContext
	secret        []byte
}

func (c *context) computeNonce() ([]byte, error) {
	Nn := aeads[c.suite.AEAD].Nn()
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, c.sequence)
	nonce := make([]byte, Nn)
	copy(nonce, c.baseNonce)
	subtle.XORBytes(nonce[Nn-8:], c.baseNonce[Nn-8:], buf)

	for _, n := range c.nonces {
		if subtle.ConstantTimeCompare(nonce, n) == 1 {
			return nil, errs.NewDuplicate("computed nonce is used before")
		}
	}
	c.nonces = append(c.nonces, nonce)
	return nonce, nil
}

func (c *context) incrementSeq() error {
	Nn := aeads[c.suite.AEAD].Nn()
	if c.sequence >= (1<<(8*Nn))-1 {
		return errs.NewFailed("message limit reached")
	}
	c.sequence++
	return nil
}

// export takes as input a context string exporter_context and a desired length L in bytes, and produces a secret derived from the internal exporter secret using the corresponding KDF Expand function. This is an interface for exporting secrets from the encryption context using a variable-length pseudorandom function (PRF), similar to the TLS 1.3 exporter interface
// https://www.rfc-editor.org/rfc/rfc9180.html#name-secret-export
func (c *context) export(exporterContext []byte, L int) ([]byte, error) {
	kdf := kdfs[c.suite.KDF]
	if L > 255*kdf.Nh() {
		return nil, errs.NewInvalidRange("L is out of range")
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
		return nil, nil, errs.WrapInvalidArgument(err, "psk arguments are invalid")
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
		return errs.NewInvalidArgument("either psk and pskId should both be nil, or none should be nil")
	}
	if gotPsk && (mode == Base || mode == Auth) {
		return errs.NewInvalidArgument("psk argument provided when not needed")
	}
	if !gotPsk && (mode == PSk || mode == AuthPSk) {
		return errs.NewInvalidArgument("mssing required psk input")
	}
	return nil
}
