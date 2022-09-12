# Proof Generation
The Client $\C$ generates a zero-knowledge proof of the validity of  $\com_\C\|\sQ'\|\sR'\|\sK_N\|\sigma_\N$, and optionally proves that the message $\sR$ of $\sR'$ satisfies some given statement $\stmt$. 

The public information is $\com_\C\|\sQ'\|\sR'\|\sK_N\|\sigma_\N$, the public key $pk_\N$ of $\N$, the query template $\mathsf{Query}$, and the statement $\stmt$. The witness is $(\theta, \sK_\C, r)$. The Client proves the following statement:

1. $\sigma_\N$ is a valid signature of $(\com_\C\|\sQ'\|\sR'\|\sK_\N)$ under the public key $pk_\N$.
    - Note that this step could be moved to outside of the zkp, if the third-party verifier could directly check the validity of the signature.

2. $\com_\C = \sha(\sK_\C\|r)$.

3. $\sQ = \mathsf{Query}(\theta)$.

4. $\sQ' = \aesgcm(\sK_\C\oplus\sK_\N,\sIV,\sQ,\sA)$.

5. $\sR' = \aesgcm(\sK_\C\oplus\sK_\N,\sIV',\sR,\sA)$. 

6. $\stmt(\sR) = 1$.