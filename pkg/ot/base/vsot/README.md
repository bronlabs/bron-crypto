# `vsot`: Verified Simplest Oblivious Transfer
This package implements the "Verified Simplest OT", as defined in "protocol 7" of
[DKLs18](https://eprint.iacr.org/2018/499.pdf). The original "Simplest OT" protocol
is presented in [CC15](https://eprint.iacr.org/2015/267.pdf). In our implementation,
we run OTs for multiple choice bits in parallel. Furthermore, as described in the 
DKLs18 paper, we implement this as Randomized OT (ROT) protocol. We keep the encryption
 and decryption steps (9 and 10) from the original protocol to realize a standard OT, 
highlighting that ROT (steps 1 to 8) suffices when VSOT is used as Base OT in an
OT extension protocol such as SoftspokenOT (in `pkg/ot/extension/softspoken`).

Limitation: currently we only support batch OTs that are multiples of 8.

Ideal functionalities required:
  - We use ZKP Schnorr for the $F^{R_{DL}}_{ZK}$, implemented in `pkg/proofs/dlog/schnorr`.
  - We use HMAC for realising the Random Oracle Hash function, the key for HMAC is received as input to the protocol.

## Protocol
This protocol is parameterized by the Elliptic curve ($\mathbb{G}, G, q$),
and symmetric security parameter $\kappa = |q|$. It requires a discrete log ZKP and a hash function H. 
- **Players**: A sender $\textsf{S}$ and a receiver $\textsf{R}$.
- **Inputs**: 
    - $\textsf{R}: \omega \in \mathbb{Z}_2$, the input choice bit.
    - For Standard OT only:
        - $\textsf{S}: \alpha^0, \alpha^1 \in \mathbb{Z}_q$, the two option messages.
- **Outputs**: 
    - For Randomized OT (ROT, used for OT extension):
        - $\textsf{R}: \rho^0, \rho^1 \in \mathbb{Z}_q$, the two option messages.
        - $\textsf{S}: \rho^\omega \in \mathbb{Z}_q$, the chosen message.
    - For Standard OT:
        - $\textsf{R}: \alpha^\omega \in \mathbb{Z}_q$, the chosen message.
- **Steps**:

    *Public Key Setup*
    
    1. $\textsf{S}$: sample random $b \overset{\$}{\leftarrow} \mathbb{Z}_q$ as , compute its public key $B = bG$, computes a proof of knowledge of $b$ with $\pi = F^{R_{DL}}_{ZK}.prove(b, G)$ and sends $\pi$ and $B$ to $\textsf{R}$.
    2. $\textsf{R}$: check that $\pi$ is a valid proof of knowledge of $b$ with respect to $G$ and $B$ by running $F^{R_{DL}}_{ZK}.verify(\pi, G, B)$, abort otherwise.

    *Pad Transfer*
    
    3. $\textsf{R}$: sample random $a \overset{\$}{\leftarrow} \mathbb{Z}_q$ and compute the pad $\rho^\omega = H(a \times B)$ and a commit $A = a\cdot G + \omega \cdot B$ of its choice bit. Sends $A$ to $\textsf{S}$.
    4. $\textsf{S}$: computes two pads $\rho^0 = H(b \times A)$ and $\rho^1 = H(b \times (A-B))$.

    *Verification*

    5. $\textsf{S}$: compute a challenge $\xi = H(H(\rho^0)) \oplus H(H(\rho^1))$ and sends it to $\textsf{R}$ and sends $\xi$ to $\textsf{R}$.
    6. $\textsf{R}$: compute the response $\rho' = H(H(\rho^\omega)) \oplus (\omega \times \xi)$ and sends it to $\textsf{S}$ and sends $\rho'$ to $\textsf{S}$.
    7. $\textsf{S}$: check if $\rho' \overset{?}{=} \rho^\omega \oplus \xi$ and abort otherwise. Send the opened commitments $H(\rho^0)$ and $H(\rho^1)$ to $\textsf{R}$.  If ROT, output the option pads $\rho^0$ and $\rho^1$.
    8. $\textsf{R}$: check if $H(\rho^\omega)$ matches for your choice bit $\omega$, and abort otherwise. Check if $\xi \overset{?}{=} H(H(\rho^0)) \oplus H(H(\rho^1))$ and abort otherwise. If ROT, output the chosen pad $\rho^\omega$.

    *Message Transfer (not needed for OT extension)*
    
    9. $\textsf{S}$: Input two messages $\alpha^0$ and $\alpha^1$. Compute the padded messages $\tilde{\alpha}^0 = \alpha^0 \oplus \rho^0$ and $\tilde{\alpha}^1 = \alpha^1 \oplus \rho^1$. Send $\tilde{\alpha}^0$ and $\tilde{\alpha}^1$ to $\textsf{R}$.
    10. $\textsf{R}$: Compute the chosen message $\alpha^\omega = \tilde{\alpha}^\omega \oplus \rho^\omega$ and output it.
