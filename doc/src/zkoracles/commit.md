# Commit
This section describes the Commit phase of zkOracles protocol.

- After the Client $\C$ and the Notary $\N$ run the Query Execution phase, the Client $\C$ generates a ciphertext $\sQ'$ of query $\sQ$ under the underlying cipher suite. $\C$ and $\N$ hold the secret key shares $\sK_\C$ and $\sK_\N$, respectively.

- The Client sends $\sQ'$ to the Server $\S$, the Server responds with a ciphertext $\sR'$. Note that $\S$ always responds honestly.

- The Client commits his share $\sK_\C$ by computing $\com_\C = \mathsf{Commitment}(\sK_\C;r)$, where $r$ randomness used to generate the commitment. $\C$ sends $\com_\C\|\sQ'\|\sR'$ to the Notary $\N$.
    - Note that we could choose a zk-friendly commitment scheme here.

- The Notary signs $\com_\C\|\sQ'\|\sR'\|\sK_\N$ with his public key and outputs a signature $\sigma_\N$. The Notary sends $\sK_\N\|\sigma_\N$ to the Client.

- The Client recovers the symmetric key $\sK = \sK_\C\oplus\sK_\N$ to decrypt and authenticate $\sR'$. This step is exactly the same as in the TLS standard.


