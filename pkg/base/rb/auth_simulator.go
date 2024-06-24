package rb

import (
	crand "crypto/rand"
	"encoding/json"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/hpke"
)

var (
	_ Auth = (*simulatorAuth)(nil)

	cipherSuite = &hpke.CipherSuite{
		KDF:  hpke.KDF_HKDF_SHA256,
		KEM:  hpke.DHKEM_P256_HKDF_SHA256,
		AEAD: hpke.AEAD_AES_128_GCM,
	}
)

type simulatorAuthMessage struct {
	Ciphertext []byte `json:"ciphertext"`
	Epk        []byte `json:"epk"`
}

type simulatorAuth struct {
	coordinator Coordinator
}

func NewSimulatorAuth(coordinator Coordinator) Auth {
	return &simulatorAuth{coordinator: coordinator}
}

func (a *simulatorAuth) Send(to types.IdentityKey, message []byte) error {
	//sk := &hpke.PrivateKey{
	//	D:         a.coordinator.GetAuthKey().PrivateKey(),
	//	PublicKey: a.coordinator.GetAuthKey().PublicKey(),
	//}
	// the mode should be hpke.Auth, but for some reason I cannot make it work with Auth
	cipherText, epk, err := hpke.Seal(hpke.Base, cipherSuite, message, nil, to.PublicKey() /*sk*/, nil, nil, nil, nil, crand.Reader)
	if err != nil {
		return errs.WrapFailed(err, "cannot encrypt message")
	}

	serialisedCipherText, err := json.Marshal(&simulatorAuthMessage{
		Ciphertext: cipherText,
		Epk:        epk.ToAffineCompressed(),
	})
	if err != nil {
		return errs.WrapSerialisation(err, "cannot serialize message")
	}

	return a.coordinator.Send(to, serialisedCipherText)
}

func (a *simulatorAuth) Receive() (types.IdentityKey, []byte, error) {
	from, message, err := a.coordinator.Receive()
	var cipherText simulatorAuthMessage
	err = json.Unmarshal(message, &cipherText)
	if err != nil {
		return nil, nil, errs.WrapSerialisation(err, "cannot deserialise message")
	}

	sk := &hpke.PrivateKey{
		D:         a.coordinator.GetAuthKey().PrivateKey(),
		PublicKey: a.coordinator.GetAuthKey().PublicKey(),
	}
	epk, err := p256.NewCurve().Element().FromAffineCompressed(cipherText.Epk)
	if err != nil {
		return nil, nil, errs.WrapSerialisation(err, "cannot deserialise ephemeral public key")
	}
	// the mode should be hpke.Auth, but for some reason I cannot make it work with Auth
	plainText, err := hpke.Open(hpke.Base, cipherSuite, cipherText.Ciphertext, nil, sk, epk /*from.PublicKey()*/, nil, nil, nil, nil)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "cannot decrypt message")
	}

	return from, plainText, nil
}

func (a *simulatorAuth) GetCoordinator() Coordinator {
	return a.coordinator
}
