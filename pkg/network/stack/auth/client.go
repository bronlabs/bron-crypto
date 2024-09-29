package auth

import (
	"bytes"
	crand "crypto/rand"
	"encoding/gob"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/encryptions/hpke"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/coordinator"
)

var (
	_ Client = (*authClientImpl)(nil)

	cipherSuite = &hpke.CipherSuite{
		KDF:  hpke.KDF_HKDF_SHA256,
		KEM:  hpke.DHKEM_P256_HKDF_SHA256,
		AEAD: hpke.AEAD_CHACHA_20_POLY_1305,
	}
)

type message struct {
	Epk        curves.Point
	CipherText []byte
}

type authClientImpl struct {
	id         types.AuthKey
	downstream coordinator.Client

	incoming chan *exchange
	outgoing chan *exchange
}

func (c *authClientImpl) SendTo(to types.IdentityKey, payload []byte) {
	c.outgoing <- &exchange{
		toFrom:  to,
		payload: payload,
	}
}

func (c *authClientImpl) Recv() (types.IdentityKey, []byte) {
	in := <-c.incoming
	return in.toFrom, in.payload
}

func (c *authClientImpl) GetAuthKey() types.AuthKey {
	return c.id
}

func (c *authClientImpl) processOutgoing() {
	hpkeSk := &hpke.PrivateKey{
		PublicKey: c.id.PublicKey(),
		D:         c.id.PrivateKey(),
	}

	for {
		out := <-c.outgoing
		to, payload := out.toFrom, out.payload

		ct, epk, err := hpke.Seal(hpke.Auth, cipherSuite, payload, nil, to.PublicKey(), hpkeSk, nil, nil, nil, crand.Reader)
		if err != nil {
			panic(err) // TODO: use context
		}
		msg := &message{
			Epk:        epk,
			CipherText: ct,
		}
		encryptedPayload := new(bytes.Buffer)
		enc := gob.NewEncoder(encryptedPayload)
		err = enc.Encode(msg)
		if err != nil {
			panic(err) // TODO: use context
		}
		c.downstream.SendTo(to, encryptedPayload.Bytes())
	}
}

func (c *authClientImpl) processIncoming() {
	sk := &hpke.PrivateKey{
		PublicKey: c.id.PublicKey(),
		D:         c.id.PrivateKey(),
	}

	for {
		from, payload := c.downstream.Recv()
		dec := gob.NewDecoder(bytes.NewReader(payload))
		var msg message
		err := dec.Decode(&msg)
		if err != nil {
			panic(err) // TODO: use context
		}

		decrypted, err := hpke.Open(hpke.Auth, cipherSuite, msg.CipherText, nil, sk, msg.Epk, from.PublicKey(), nil, nil, nil)
		if err != nil {
			panic(err)
		}

		c.incoming <- &exchange{
			toFrom:  from,
			payload: decrypted,
		}
	}
}
