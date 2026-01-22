package softspoken

import (
	"bytes"
	"encoding/gob"

	"github.com/bronlabs/errs-go/pkg/errs"
)

type challengeResponseDTO struct {
	X [SigmaBytes]byte
	T [Kappa][SigmaBytes]byte
}

type round1P2PDTO struct {
	U                 [Kappa][]byte // [κ][η']bits
	ChallengeResponse challengeResponseDTO
}

func (r1 *Round1P2P) GobEncode() ([]byte, error) {
	dto := &round1P2PDTO{
		U: r1.U,
		ChallengeResponse: challengeResponseDTO{
			X: r1.ChallengeResponse.X,
			T: r1.ChallengeResponse.T,
		},
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(dto)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("cannot serialise Round1P2P message")
	}
	return buf.Bytes(), nil
}

func (r1 *Round1P2P) GobDecode(data []byte) error {
	var out round1P2PDTO
	dec := gob.NewDecoder(bytes.NewReader(data))
	err := dec.Decode(&out)
	if err != nil {
		return errs.Wrap(err).WithMessage("cannot deserialize Round1P2P message")
	}

	r1.U = out.U
	r1.ChallengeResponse.X = out.ChallengeResponse.X
	r1.ChallengeResponse.T = out.ChallengeResponse.T
	return nil
}
