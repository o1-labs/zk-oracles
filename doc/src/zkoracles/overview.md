# ZkOracles
With the widespread deployment of TLS standard, users can access private data over channels with end-to-end confidentiality and integrity. However, this private data is locked up at its point of origin, because the users can not prove to third parties the provenance of such data.

zkOracles is a decentralized protocol that allows users to prove that a piece of data accessed via TLS came from a particular service provider, and optionally prove statements about such data in zero-knowledge.

Unlike other solutions that require trusted hardware or server-side modifications, zkOracles requires no server-side cooperation. Thus zkOracles enables anyone to prove his data from any website.


There are three roles involves in zkOracles. The Client ($\mathcal{C}$), with the help of the Notary ($\mathcal{N}$), that will establish a TLS channel with the Server ($\mathcal{S}$).

## The Transport Layer Security (TLS) Protocol
The TLS protocol is composed of two protocols: the TLS Handshake Protocol and the TLS Record Protocol.

The TLS Handshake Protocol allows the server and client to authenticate each other and to negotiate an encryption algorithm and cryptographic keys before the application protocol transmits or receives its first byte of data.

The TLS Record Protocol provides private and reliable connections for data transmission. Symmetric cryptography is used for data encryption and a keyed MAC is used for message integrity check.

The following workflow is a simplified version of TLS 1.2.

``` text
Client                              Server
[Handshake]                         [Handshake]
ClientHello         ----->        
                                    ServerHello
                                    Certificate
                                    ServerKeyExchange
                                    ServerHelloDone
                    <-----
ClientKeyExchange
CertificateVerify
[ChangeCipherSpec]
Finished
                    ----->          
                                    [ChangeCipherSpec]
                                    Finished

[Record]                            [Record]
Data                <---->          Data
```


### ZkOracles Overview
In zkOracles, the Client holds a secret parameter $\theta_s$ (e.g., a password), a publicly known query template $\mathsf{Query}$ and a statement $\mathsf{Stmt}$. Note that $\mathsf{Query}$ and $\mathsf{Stmt}$ are application-related.

A query template is a function that takes as input $\theta_s$ and returns a complete query. For instance, $\mathsf{Query}(\theta_s)$ = "Price of MINA on 31th August 2022 with API key = $\theta_s$". The query is sent to the Server, and the Client will prove that the sent query is well-formed without revealing the secret.

After receiving the response $\mathsf{R}$ from the Server, the Client will prove that $\mathsf{R}$ satisfies $\mathsf{Stmt}$ without revealing $\mathsf{R}$. Following the previous example, as the response $\mathsf{R}$ is a number, the following statement would compare it with a threshold: $\mathsf{Stmt}(\mathsf{R})$ = "$\mathsf{R}$ > \$ 5.00".

The critical point here is that the protocol has to ensure that the query and response are derived from a TLS connection between the Client and Server. Therefore, we can not let the Client to establish a TLS connection with the Server alone, because he/she can encrypt arbitrary messages using the session key and claims that these messages come from a TLS connection with the Server.

ZkOracles provides a protocol that the Notary and Client collaboratively play the role of "TLS Client" to establish a TLS connection with the Server. More specifically, the Notary and the Client run several secure two-party computation protocols to generate necessary information for a "TLS Client", which keep the secret from Client private against the Notary. 

The following workflow is an overview of the zkOracle protocol.



``` text
Notary                              Client                              Server
[3PC-Handshake]                     [3PC-Handshake]                     [Handshake]
                                    ClientHello         ----->          
                                                                        ServerHello
                                                                        Certificate
                                                                        ServerKeyExchange
                                                                        ServerHelloDone
                                                        <-----
                |---------|                      
            --->|2PC Prot.|<---
                |---------|        
                                    ClientKeyExchange
                                    CertificateVerify
                                    [ChangeCipherSpec]
                                    Finish
                                                        ----->          [ChangeCipherSpec]
                                                                        Finished
                |---------|                      
            --->|2PC Prot.|<---
                |---------| 

Key share k_N                       Key share k_C                       Key k_S (k_S = k_N XOR k_C)

[Query Execution]                   [Query Execution]                   [Record]
            
                |---------|<--- k_C
        k_N --->|2PC Prot.|
                |---------|<--- Query(Q)

                                    Encrypted Q'
                                                        ----->
[Commit]                            [Commit]                            [Record]

                                                        <----           Encrypted R'
                                    
                                    Commit(k_C)[optional]
                                    Encrypted Q'
                                    Encrypted R'
                <-----

k_N
                ----->                                    

                                    [Proof Generation]
                                    Generate a ZKP proof.
```


The zkOracles protocol consists of four phases: 3PC-Handshake, Query Execution, Commit and Proof Generation. Note that the zkOracles protocol is transparent to the Server. The Server runs the standard TLS protocol.

- [**3PC-Handshake**] 
In this phase, the Notary and the Client run several two-party computation protocols to handle the TLS Handshake Protocol with the Server. At the end of this phase, the Notary obtains a session key share $k_\mathcal{N}$, the Client obtains another key share $k_\mathcal{C}$. Note that $k_\mathcal{N}\oplus k_\mathcal{C}$ is the full session key. The detailed description will be given in the next section.

- [**Query Execution**]
In this phase, the Client takes as private input $\mathsf{Q}=\mathsf{Query}(\theta_s)$ and the key share $k_\mathcal{C}$. He/she runs a two-party computation protocol with the Notary with private input $k_\mathcal{N}$. The protocol outputs a ciphertext $\mathsf{Q}'$ of $\mathsf{Q}$ under the key $k_{\mathcal{N}}\oplus k_{\mathcal{C}}$ to the Client. The Client sends $\mathsf{Q}'$ to the Server.
This protocol is highly related to the cipher suite used in TLS. The detailed description will be given in the next section.

- [**Commit**]
In this phase, the Client first commits the key share $k_\mathcal{C}$ to the Notary. Note that this step is optional, it could be omitted if committing cipher suite is used. Then the Client sends $\mathsf{Q}'$ and $\mathsf{R}'$ to the Notary. The Notary signs $\textsf{Commit}(k_\mathcal{C})\|\mathsf{Q}'\|\mathsf{R}'\|k_\mathcal{N}$ and sends the signature $\sigma_\mathcal{N}$ and $k_\mathcal{N}$ to the Client. The Client recovers the session key by computing $k_\mathcal{N}\oplus k_\mathcal{C}$, then decrypts $\mathsf{R}'$ to $\mathsf{R}$.
The detailed description will be given in the next section.

- [**Proof Generation**]
In this phase, the Client generates a zero-knowledge proof stating that "$\sigma_\mathcal{N}$ is a valid signature, $k_{\mathsf{C}}$ is committed in $\mathsf{Commit}(k_{\mathsf{C}})$, $\mathsf{Q}$' is decrypted to $\mathsf{Q}$ s.t. $\mathsf{Q} = \mathsf{Query}(\theta_s)$, $\mathsf{R}$' is decrypted to $\mathsf{R}$ with the same session key s.t. $\mathsf{Stmt}(\mathsf{R}) = 1$". The detailed description will be given in the next section.
