package boolexpr

import (
	"github.com/bronlabs/errs-go/errs"

	"github.com/bronlabs/bron-crypto/internal/tags"
	"github.com/bronlabs/bron-crypto/pkg/base/serde"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/internal"
)

const ThresholdGateAccessStructureTag = tags.ThresholdGateAccessStructureTag

func init() {
	serde.Register[*ThresholdGateAccessStructure](ThresholdGateAccessStructureTag)
}

type thresholdGateAccessStructureDTO struct {
	Root         *Node                `cbor:"root"`
	Shareholders map[internal.ID]bool `cbor:"shareholders"`
}

func (a *ThresholdGateAccessStructure) MarshalCBOR() ([]byte, error) {
	dto := &thresholdGateAccessStructureDTO{
		Root:         a.root,
		Shareholders: a.shareholders,
	}
	data, err := serde.MarshalCBORTagged(dto, ThresholdGateAccessStructureTag)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal ThresholdGateAccessStructure")
	}
	return data, nil
}

func (a *ThresholdGateAccessStructure) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*thresholdGateAccessStructureDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal ThresholdGateAccessStructure")
	}
	if dto == nil {
		return internal.ErrSerialisation.WithMessage("nil ThresholdGateAccessStructure data")
	}
	shareHoldersInNode := make(map[internal.ID]bool)
	allShareholders(dto.Root, shareHoldersInNode)
	for shareholder := range dto.Shareholders {
		if !shareHoldersInNode[shareholder] {
			return internal.ErrSerialisation.WithMessage("shareholder in shareholders map not found in threshold gate tree")
		}
	}
	for shareholder := range shareHoldersInNode {
		if !dto.Shareholders[shareholder] {
			return internal.ErrSerialisation.WithMessage("shareholder in threshold gate tree not found in shareholders map")
		}
	}
	if err := checkTree(dto.Root); err != nil {
		return errs.Wrap(err).WithMessage("invalid threshold gate tree")
	}
	a.root = dto.Root
	a.shareholders = dto.Shareholders
	return nil
}

type nodeDTO struct {
	Kind      GateKind    `cbor:"kind"`
	Attr      internal.ID `cbor:"attr,omitempty"`
	Threshold int         `cbor:"threshold,omitempty"`
	Children  []*Node     `cbor:"children,omitempty"`
}

func (n *Node) toDTO() *nodeDTO {
	if n == nil {
		return nil
	}
	dto := &nodeDTO{
		Kind:      n.kind,
		Attr:      n.attr,
		Threshold: n.threshold,
		Children:  n.children,
	}
	return dto
}

func (n *Node) MarshalCBOR() ([]byte, error) {
	dto := n.toDTO()
	data, err := serde.MarshalCBOR(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to marshal Node")
	}
	return data, nil
}

func (n *Node) UnmarshalCBOR(data []byte) error {
	dto, err := serde.UnmarshalCBOR[*nodeDTO](data)
	if err != nil {
		return errs.Wrap(err).WithMessage("failed to unmarshal Node")
	}
	if dto == nil {
		return internal.ErrSerialisation.WithMessage("nil Node data")
	}
	if dto.Kind == gate && (dto.Threshold < 1 || len(dto.Children) == 0 || dto.Threshold > len(dto.Children)) {
		return internal.ErrSerialisation.WithMessage("invalid gate node: threshold must be positive and at most the number of children")
	}
	if dto.Kind == attribute && dto.Attr == 0 {
		return internal.ErrSerialisation.WithMessage("invalid attribute node: attr must be non-zero")
	}
	n.kind = dto.Kind
	n.attr = dto.Attr
	n.threshold = dto.Threshold
	n.children = dto.Children
	return nil
}
