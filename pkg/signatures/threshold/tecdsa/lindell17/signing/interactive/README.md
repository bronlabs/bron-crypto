In the original Lindell 2017 paper parties jointly compute $s$ part of the signature using the following equation:
$$s=k_1^{-1}k_2^{-1}\left(H(m)+ry_1y_2\right)$$
where $k_i$ are multiplicative shares of cryptographically secure random integer $k$ (aka "nonce") i.e.  ($k=k_1k_2$) and $y_i$ are multiplicative shares of private key $y$ (i.e. $y=y_1y_2$).

However we are using Shamir sharing of secret key $y$ i.e. $y=\frac{y_1x_2 - y_2x_1}{x_2-x_1}$ (linear interpolation), where $x_i$ are Shamir indices (known to every party) and $y_i$ are Shamir shares kept secret. Plugging that in to the $s$ equation get:
$$s=k_1^{-1}k_2^{-1} \left( H(m)+r\frac{y_1x_2-y_2x_1}{x_2-x_1} \right) $$
$$s=k_1^{-1}\left(k_2^{-1}H(m)+k_2^{-1}r\left(\frac{y_1x_2-y_2x_1}{x_2-x_1}\right)\right)$$
$$s=k_1^{-1}\left(k_2^{-1}H(m)+k_2^{-1}r\left(y_1\frac{-x_2}{x_1-x_2}+y_2\frac{-x_1}{x_2-x_1}\right)\right)$$
$$s=k_1^{-1}\left(k_2^{-1}H(m)+k_2^{-1}ry_1\lambda_1+k_2^{-1}ry_2\lambda_2\right)$$

Where $\lambda_i$ are Lagrange coefficients of Shamir polynomial.
Let $c_1=k_2^{-1}H(m)$ and $c_2=k_2^{-1}ry_1\lambda_1+k_2^{-1}ry_2\lambda_2$
and we get:
$$s=k_1^{-1}\left(c_1+c_2\right)$$
Let $c_3=c_1+c_2$ and we end up with:
$$s=k_1^{-1}c_3$$
The secondary party is able to compute Paillier encryption of $c_3$ using Paillier public key of primary party. It then sends is to primary party where it is decrypted and multiplied by $k_1^{-1}$ to compute $s$.
