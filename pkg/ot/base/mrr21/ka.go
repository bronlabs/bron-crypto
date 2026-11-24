package mrr21

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"slices"

	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/ot"
)

// kaKeyLabel prefixes the HKDF info of the key agreement, separating its keys
// from every other HKDF use in this repository; the instance tag follows it.
const kaKeyLabel = "BRON_CRYPTO-MRR21-TAGGED_ECDHKA-"

// deriveKey is the key-derivation step of the tagged Diffie–Hellman key
// agreement of MRR21 (Section 4.1 and Figure 3): both KA.key1(a, B, τ) and
// KA.key2(b, A, τ) equal H(ab·G, τ), here with H instantiated as HKDF-SHA256
// over the encoding of the shared point, with the tag bound through the HKDF
// info (label ‖ tag) so that keys under different tags are independent, which
// is the tag non-malleability the batch OT needs (Definition 3, from the
// tagged ODH assumption, Definition 21). The tag is the OT instance index and
// branch, i ‖ j, in MRR21 Figure 3.
//
// salt is the HKDF extraction salt: a non-secret value shared by both parties,
// such as a session identifier, or nil for the zero salt of RFC 5869. local is
// the caller's secret exponent and must stay secret: it is reused across the
// whole batch, and whoever learns it computes both OT messages of every
// instance. remote is the other party's message a·G or b·G; it must be a
// validated element of the prime-order group and not the identity, because
// the identity yields a shared point known to everyone. Constant-time
// behaviour in local relies on the group's ScalarOp implementation. The key
// length is that of the message type M.
func deriveKey[M ot.Message, G algebra.PrimeGroupElement[G, S], S algebra.PrimeFieldElement[S]](tag []byte, local S, remote G, salt []byte) (M, error) {
	var key M
	if utils.IsNil(local) {
		return key, ot.ErrInvalidArgument.WithMessage("local exponent must not be nil")
	}
	if local.IsZero() {
		return key, ot.ErrInvalidArgument.WithMessage("local exponent must not be zero")
	}
	if utils.IsNil(remote) {
		return key, ot.ErrInvalidArgument.WithMessage("remote message must not be nil")
	}
	if remote.IsOpIdentity() {
		return key, ot.ErrInvalidArgument.WithMessage("remote message must not be the identity")
	}

	shared := remote.ScalarOp(local)
	if shared.IsOpIdentity() {
		return key, ot.ErrInvalidArgument.WithMessage("shared point is the identity")
	}
	info := string(slices.Concat([]byte(kaKeyLabel), tag))
	raw, err := hkdf.Key(sha256.New, shared.Bytes(), salt, info, len(key))
	if err != nil {
		return key, errs.Wrap(err).WithMessage("cannot derive key of %d bits with HKDF", ot.MessageBitLen[M]())
	}
	copy(ot.MessageAsSlice(&key), raw)
	return key, nil
}

// deriveKeyAgreementTag is the tag i ‖ j of MRR21 Figure 3: the branch bit
// followed by the little-endian instance index.
func deriveKeyAgreementTag(i int, ci byte) []byte {
	return binary.LittleEndian.AppendUint32([]byte{ci}, uint32(i))
}
