## K Pattern

Let's denote $s_I,e,rs,re$ are participant static private key, ephemeral private key, other party static public key and ephemeral public key respectively. Static public key of other participant is known by another party before handshaking.

* 1.1. Each party generates ephemeral key pair $(e, e.pk)$ before handshaking
* 1.2. Before establishing handshaking each party initialise symmetric state $ss$ as follows: $ss.h = H(H(n) || sid || rs || s.pk)$ and $ss.k = H(n)$ where $H$ is a hash function, $n$ is protocol name, $sid$ is session id and $s.pk$ is static public key of the private key $s$

### Round 1

2.1 Initiator side

* 2.1.1 hash current state with another party pk $ss.h = H(ss.h || e.pk)$
* 2.1.2 generate psuedorandom $ss.k = MixKey(ss.k, DH(e, rs), DH(s, rs))$. View spec for more detail [MixKey](https://noiseprotocol.org/noise.html#the-symmetricstate-object) function
* 2.1.3 Generate encrypted handshake message for validating $m_c = Encrypt(ss, m)$
* 2.1.4 Generate symmetric key $cs = Split(ss)$. View spec for more detail [Split](https://noiseprotocol.org/noise.html#the-symmetricstate-object) function

$m_c$ is sent to Responder. $cs$ can be used to encrypt message.

2.2 Responder side

* 2.2.1 $ss.h = H(ss.h || re.pk)$
* 2.2.2 $ss.k = MixKey(ss.k, DH(s, re), DH(s, rs))$
* 2.2.3 $m = Decrypt(ss, m_c)$ and verify $m$ is valid
* 2.2.4 $cs = Split(ss)$

$cs$ can be used to decrypt message.
