package softspoken

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/pkg/base/binaryfields/bf128"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/ot"
	"github.com/bronlabs/bron-crypto/pkg/ot/extension/iknp03"
)

// RoundExtendP2P is the receiver's only message of an extension: the F_COTe
// columns and the consistency-check responses x̄ and t̄¹..t̄^κ.
type RoundExtendP2P struct {
	COTEMessage *iknp03.RoundExtendP2P[Message]
	XResponse   *bf128.FieldElement
	TResponse   []*bf128.FieldElement
}

type roundExtendP2PDTO struct {
	COTEMessage *iknp03.RoundExtendP2P[Message] `cbor:"cote"`
	XResponse   []byte                          `cbor:"x"`
	TResponse   [][]byte                        `cbor:"t"`
}

// Validate checks that the message comes from the sender's counterparty, that
// its F_COTe part is valid for ℓ' = ℓ + sigma with ℓ a positive multiple of
// sigma, and that it carries x̄ and exactly κ responses t̄ⁱ.
func (m *RoundExtendP2P) Validate(sender *Sender, senderID sharing.ID) error {
	if m == nil || sender == nil {
		return ot.ErrValidation.WithMessage("message and sender must not be nil")
	}
	if senderID != sender.copartyID {
		return ot.ErrValidation.WithMessage("message from party %d, expected %d", senderID, sender.copartyID)
	}
	if m.COTEMessage == nil {
		return ot.ErrValidation.WithMessage("COTe message must not be nil")
	}
	if err := m.COTEMessage.Validate(sender.cote, senderID); err != nil {
		return errs.Wrap(err).WithMessage("invalid COTe message")
	}
	lPrime := len(m.COTEMessage.U[0]) * 8
	if lPrime%sigma != 0 || lPrime < 2*sigma {
		return ot.ErrValidation.WithMessage("message extends %d OTs, expected a multiple of %d of at least %d", lPrime, sigma, 2*sigma)
	}
	if m.XResponse == nil {
		return ot.ErrValidation.WithMessage("x response must not be nil")
	}
	if kappa := ot.MessageBitLen[Message](); len(m.TResponse) != kappa {
		return ot.ErrValidation.WithMessage("message holds %d t responses, expected %d", len(m.TResponse), kappa)
	}
	for i, ti := range m.TResponse {
		if ti == nil {
			return ot.ErrValidation.WithMessage("t response %d must not be nil", i)
		}
	}
	return nil
}

// MarshalCBOR encodes the F_COTe message and the responses as field-element bytes.
func (m *RoundExtendP2P) MarshalCBOR() ([]byte, error) {
	if m == nil || m.XResponse == nil {
		return nil, ot.ErrInvalidArgument.WithMessage("message and x response must not be nil")
	}
	t := make([][]byte, len(m.TResponse))
	for i, ti := range m.TResponse {
		if ti == nil {
			return nil, ot.ErrInvalidArgument.WithMessage("t response %d must not be nil", i)
		}
		t[i] = ti.Bytes()
	}
	out, err := serde.MarshalCBOR(&roundExtendP2PDTO{COTEMessage: m.COTEMessage, XResponse: m.XResponse.Bytes(), TResponse: t})
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal extend message")
	}
	return out, nil
}

// UnmarshalCBOR decodes the message, parsing the responses as elements of
// F_{2^sigma}. This is a deserialisation trust boundary; the structural checks
// that need the sender's parameters are done by Validate.
func (m *RoundExtendP2P) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[roundExtendP2PDTO](data)
	if err != nil {
		return errs.Join(ot.ErrSerialisation, errs.Wrap(err)).WithMessage("failed to unmarshal extend message")
	}
	field := bf128.NewField()
	x, err := field.FromBytes(dto.XResponse)
	if err != nil {
		return errs.Join(ot.ErrInvalidArgument, errs.Wrap(err)).WithMessage("invalid x response in unmarshalled data")
	}
	t := make([]*bf128.FieldElement, len(dto.TResponse))
	for i, raw := range dto.TResponse {
		t[i], err = field.FromBytes(raw)
		if err != nil {
			return errs.Join(ot.ErrInvalidArgument, errs.Wrap(err)).WithMessage("invalid t response %d in unmarshalled data", i)
		}
	}
	*m = RoundExtendP2P{COTEMessage: dto.COTEMessage, XResponse: x, TResponse: t}
	return nil
}
