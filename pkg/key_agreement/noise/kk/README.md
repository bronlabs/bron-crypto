## KK Pattern

Let's denote $s_I,e,rs,re$ are participant static private key, ephemeral private key, other party static public key and ephemeral public key respectively. Static public key of other participant is known by another party before handshaking.

* 1.1. Each party generates ephemeral key pair $(e, e.pk)$ before handshaking
* 1.2. Before establishing handshaking each party initialise symmetric state $ss$ as follows: $ss.h = H(H(n) || sid || rs || s.pk)$ and $ss.k = H(n)$ where $H$ is a hash function, $n$ is protocol name, $sid$ is session id and $s.pk$ is static public key of the private key $s$

### Round 1

3.1 Initiator side

* 3.1.1 $ss.h = H(ss.h || e.pk)$
* 3.1.2 $ss.k = MixKey(ss.k, DH(e, rs), DH(s, rs))$
* 3.1.3 $m_c = Encrypt(ss, m)$

Send $m_c$ to Responder

3.2 Responder side

* 3.2.1 $ss.h = H(ss.h || re.pk)$
* 3.2.2 $ss.k = MixKey(ss.k, DH(s, re), DH(s, rs))$
* 3.2.3 $m = Decrypt(ss, m_c)$ and verify $m$ is valid

Check $m$ is valid as both parties should agree on the same message. Additionally, Responder also need to go through the following steps:

* 3.3.1 $ss.h = H(ss.h || e.pk)$
* 3.3.2 $ss.k = MixKey(ss.k, DH(e, re), DH(s, re))$
* 3.3.3 $\{cs1,cs2\} = Split(ss)$
* 3.3.4 $m_c = Encrypt(ss, m)$

$m_c$ is sent to Initiator for validating and complete handshaking. $cs1$ and $cs2$ can be used to encrypt and decrypt message.

### Round 2

4.2 Initiator side

Initiator received $m_c$ and go through the same steps 3.3.1 to 3.3.3 as Responder in round 2. Additionally, Initiator also need to go through the following steps:

* 4.3.4 $m = Decrypt(ss, m_c)$ and verify $m$ is valid

Check $m$ is valid as both parties should agree on the same message
