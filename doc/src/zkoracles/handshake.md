# 3PC Handshake
This section describes in detail the 3PC handshake phase in zkOracles protocol.

In this version, we focus on TLS 1.2 and the TLS-compatible ECDHE key exchange protocol. 

## Notation and Preliminaries

- Let $\EC$ denote the EC group with base field $\Fq$ and scale field $\Fp$ used in ECDHE.
- Let $G$ denote the generator of $\EC$.
- Given $a\in\Fp$, uniformly random $x,y\in\Fp$ are additive shares of $a$ if $x+y = a\mod p$.
- Given $a\in \{0,1\}^k$, uniformly random $x,y \in\{0,1\}^k$ are boolean shares of $a$ if $x\oplus y = a$.

## 3PC Handshake Protocol
1. The Client $\C$ samples uniformly random $r_\C\leftarrow \{0,1\}^{256}$ and sends $\mathsf{ClientHello}(r_{\C})$ to the Server $\S$ to start a standard TLS handshake.

2. The Server sends $\mathsf{ServerHello}(r_\S)$, $\mathsf{ServerKeyExchange}(Y_\S,\sigma,\mathsf{cert})$ as in a standard TLS handshake. Let $Y_\S = s_\S\cdot G$.

3. $\C$ verifies that $\mathsf{cert}$ is a valid certificate and that $\sigma$ is a valid signature over $(r_\C, r_\S, Y_\S)$ signed by a key contained in $\mathsf{cert}$.

4. $\C$ sends $(r_\C, r_\S, Y_\S, \sigma, \mathsf{cert})$ to the Notary $\N$.

5. $\N$ verifies that $\mathsf{cert}$ is a valid certificate and that $\sigma$ is a valid signature over $(r_\C, r_\S, Y_\S)$ signed by a key contained in $\mathsf{cert}$.

6. $\N$ samples uniformly random $s_\N\leftarrow \Fp$ and computes $Y_\N = s_\N\cdot G$ and sends $Y_\N$ to $\C$.

7. $\C$ samples uniformly random $s_\C\leftarrow \Fp$ and computes $Y_\C = s_\C\cdot G$ and sends $\mathsf{ClientKeyExchange}(Y_\N+Y_\C)$ to $\S$.

8. $\C$ locally computes $P_\C = s_\C\cdot Y_\S$, $\N$ locally computes $P_\N = s_\N\cdot Y_\S$.

9. $\C$ and $\N$ run a 2PC protocol $\pi_{\mathsf{2PC}}^{\mathsf{ECtF}}$ to compute an additive share of the $x$-coordinate of $s_\S\cdot (Y_\N+Y_\C) = s_\N\cdot Y_\N + s_\C\cdot Y_\C$, denoted as $z_\C$ and $z_\N$ respectively. The details of $\pi_{\mathsf{2PC}}^{\mathsf{ECtF}}$ will be given later.

10. $\C$ and $\N$ take as private input $z_\C$ and $z_\N$ respectively, and run a 2PC protocol $\pi_{\mathsf{2PC}}^{\mathsf{Der}}$ to derive boolean shares of master key and session key. $\C$ receives ($\mathsf{mk}_\C,\mathsf{sk}_\C$), $\N$ receives ($\mathsf{sk}_\N,\mathsf{sk}_\N$). The details of $\pi_{\mathsf{2PC}}^{\mathsf{Der}}$ will be given later.

11. $\C$ computes a hash ${h}$ of the handshake messages sent and received so far, and runs a 2PC protocol $\pi_{\mathsf{2PC}}^{\mathsf{PRF}}$ with $\N$ to compute 
$s = \mathsf{PRF}(\mathsf{mk}_\C\oplus\mathsf{mk}_\N, ``\mathsf{client~finished}", h)$ and sends $\mathsf{Finished}(s)$ to $\S$.

12. On receiving $\mathsf{Finished}(s)$ from $\S$, $\C$ and $\N$ run a 2PC protocol $\pi_{\mathsf{2PC}}^\mathsf{PRFCheck}$ to check $s = \mathsf{PRF}(\mathsf{mk}_\C\oplus\mathsf{mk}_\N, ``\mathsf{server~finished}", h)$, and abort if not.

The subprotocols are described as follows. Note that $\pi_{\mathsf{2PC}}^{\mathsf{Der}}$, $\pi_{\mathsf{2PC}}^{\mathsf{PRF}}$ and $\pi_{\mathsf{2PC}}^\mathsf{PRFCheck}$ use general-purpose 2PC protocols, which will be specified in the next section. Therefore, for these three protocols only the computed functions are specified in this section.


### The $\pi_{\mathsf{2PC}}^{\mathsf{ECtF}}$ Protocol
This protocol invokes another sub protocol called $\mathsf{MtA}$. $\mathsf{MtA}$ is a Multiplicative-to-Additive share-conversion protocol. $(\alpha, \beta) \leftarrow \mta(a,b)$ denotes a run of $\mta$ between Alice and Bob with inputs $a,b\in\Fq$, and outputs $\alpha,\beta\in\Fq$,respectively. It satisfies that $\alpha+\beta = a\cdot b\mod q$. The protocol could be generalized to handle vector inputs. Namely, for vectors $\vec{a},\vec{b}\in\mathbb{F}_q^n$, if $(\alpha,\beta)\leftarrow \mta(\vec{a},\vec{b})$, then $\innerprod{\vec{a}}{\vec{b}} = \alpha+\beta\mod q$.
We refer to [GG18](https://eprint.iacr.org/2019/114.pdf) for a Paillier-based construction.

TODO: specify the details of the $\mta$ protocol.

The ECtF protocol converts shares in the EC group into additive shares in $\Fq$. The inputs are two EC points $P_\C = (x_\C,y_\C)$ and $P_\N = (x_\N,y_\N)$. Suppose $(x,y) = P_\C+P_\N$, the output of this protocol is $z_\C,z_\N\in\Fq$ such that $z_\C+z_\N = x \mod q$. Specifically, for the curve considered in TLS, $x = \lambda^2 - x_\C - x_\N$ where $\lambda = (y_\N-y_\C)/(x_\N-x_\C)$.

The ECtF protocol is as follows.

1. $\C$ and $\N$ sample $\rho_i\leftarrow \Fq$ for $i\in\{\C,\N\}$ respectively. $\C$ and $\N$ run $(\alpha_\C,\alpha_\N)\leftarrow \mta((-x_\C,\rho_\C),(\rho_\N,x_\N))$.

2. $\C$ locally computes $\delta_\C = -x_\C\rho_\C + \alpha_\C$, $\N$ locally computes $\delta_\N = x_\N\rho_\N + \alpha_\N$.

3. $\C$ sends $\delta_\C$ to $\N$, $\N$ sends $\delta_\N$ to $\C$. Both parties compute $\delta = \delta_\C+\delta_\N$.

4. $\C$ and $\N$ locally compute $\eta_i= \rho_i\cdot \delta^{-1}$ for $i\in\{\C,\N\}$ respectively.

5. $\C$ and $\N$ run $(\beta_\C,\beta_\N)\leftarrow\mta((-y_\C,\eta_\C),(\eta_\N, y_\N))$.

6. $\C$ locally computes $\lambda_\C = -y_\C\eta_\C+\beta_\C$, $\N$ locally computes $\lambda_\N = y_\N\eta_\N+\beta_N$. 

7. $\C$ and $\N$ run $(\gamma_\C,\gamma_\N)\leftarrow \mta(\lambda_\C,\lambda_N)$.

8. $\C$ and $\N$ computes $z_i = 2\gamma_i+\lambda_i^2 - x_i$ for $i\in\{\C,\N\}$ respectively.

9. $\C$ outputs $z_\C$ and $\N$ outputs $z_\N$.



The correctness of the ECtF protocol is analyzed as follows.

- After Step 1, $\C$ and $\N$ obtain shares $\alpha_\C$ and $\alpha_\N$ respectively such that $\alpha_\C+\alpha_\N = -x_\C\rho_\N+\rho_\C x_\N$.

- After Step 3, $\C$ and $\N$ both obtain $\delta = -x_\C\rho_\N+\rho_\C x_\N -x_\C\rho_\C + \rho_\N x_\N = (x_\N-x_\C)(\rho_\N+\rho_\C)$.

- After Step 4, $\C$ and $\N$ obtain $\eta_\C$ and $\eta_\N$ respectively, which are shares of $(x_\N-x_\C)^{-1}$. This is because $\eta_\C+\eta_\N = (\rho_\C+\rho_\N)\cdot \delta^{-1} = (x_\N-x_\C)^{-1}$.

- Step 5 and 6 are similar to Step 1 and 2. $\C$ and $\N$ obtain $\lambda_\C$ and $\lambda_\N$ respectively, which are shares of $\lambda = (y_\N-y_\C)/(x_\N-x_\C)$.

- After Step 7, $\C$ and $\N$ obtains $\gamma_\C$ and $\gamma_\N$ respectively, which are shares of $\lambda_\C\lambda_\N$.

- It is easy to show that $z_\C$ and $z_\N$ are the desired outputs, because 
$$z_\C+z_\N = \lambda_\C^2+\lambda_\N^2 + 2\lambda_\C\lambda_\N - (x_\C+x_\N) = \lambda^2 - x_\C-x_\N.$$

For the security, we refer to [this paper](https://arxiv.org/pdf/1909.00938.pdf).
### The $\pi_{\mathsf{2PC}}^{\mathsf{PRF}}$ Protocol
The PRF function is defined with the $\mathsf{P\_{hash}}$ function, where $\mathsf{hash}$ could be $\mathsf{SHA}256$ or $\mathsf{SHA}384$ according to the cipher suite. $\mathsf{P\_{hash}}$ is defined as follows.

$$\mathsf{P\_{hash}}(\mathsf{secret},\mathsf{seed}) = \mathsf{HMAC\_hash}(\mathsf{secret}, \mathsf{A}(1)\|\mathsf{seed})\Big\|\mathsf{HMAC\_hash}(\mathsf{secret}, \mathsf{A}(2)\|\mathsf{seed})\Big\|...$$

$\mathsf{A}(\cdot)$ is defined as $\mathsf{A}(0) = \mathsf{seed}$, $\mathsf{A}(i) = \mathsf{HMAC\_hash}(\mathsf{secret}, \mathsf{A}(i-1))$ for $i\geq 1$.

$\mathsf{P\_{hash}}$ can be iterated as many times as necessary to produce the required quantity of data. For example, if $\mathsf{P\_{SHA}}256$ is being used to create $80$ bytes of data, it will have to be iterated three times, creating $96$ bytes of output data; the last $16$ bytes of the final iteration will then be discarded, leaving $80$ bytes of output data.

TLS's $\mathsf{PRF}$ is created by applying $\mathsf{P\_{hash}}$ to the secret as:
$$\mathsf{PRF}(\mathsf{secret},\mathsf{label},\mathsf{seed}) = \mathsf{P\_{hash}}(\mathsf{secret}, \mathsf{label\|seed})$$

The label is an ASCII string.

The function $F_{\mathsf{PRF}}$ defined in this protocol is as follows.
$$F_{\mathsf{PRF}}(\mathsf{mk}_\C,\mathsf{mk}_\N) = \mathsf{PRF}(\mathsf{mk}_\C\oplus\mathsf{mk}_\N, ``\mathsf{client~finished}", h)$$

$h$ is public, and the output is given to $\C$.
### The $\pi_{\mathsf{2PC}}^\mathsf{PRFCheck}$ Protocol
The function $F_{\mathsf{PRFCheck}}$ computed in this protocol is as follows.
$$F_{\mathsf{PRFCheck}} = \mathsf{PRF}(\mathsf{mk}_\C\oplus\mathsf{mk}_\N, ``\mathsf{server~finished}", h) == s$$

$h,s$ are public, the output is given to $\C$.
### The $\pi_{\mathsf{2PC}}^{\mathsf{Der}}$ Protocol
The function $F_{\mathsf{Der}}((z_\C,\mathsf{mk}_\C,\mathsf{sk}_\C),z_\N)$ computed in this protocol is as follows, where $\mathsf{mk}_\C$ and $\mathsf{sk}_\C$ are uniformly chosen by $\C$ in the 3PC handshake protocol.

1. Compute $z = z_\C+z_\N\mod q$.

2. Decompose $z$ into bit string $\hat{z}$.

3. Compute $\mathsf{mk} = \mathsf{PRF}(\hat{z},``\mathsf{master~secret}", r_\C\|r_\S)$. $m$ is truncated as $48$ bytes. $r_\C$ and $r_\S$ are random strings chosen by $\C$ and $\S$ in $\mathsf{ClientHello}$ and $\mathsf{ServerHello}$, respectively.

4. Compute $\mathsf{sk} = \mathsf{PRF}(\mathsf{mk},``\mathsf{key~expansion}", r_\S\|r_\C)$. The length of $\mathsf{sk}$ depends on the chosen cipher suite. For example, $\mathsf{sk}$ is $16$-byte long for AES-128-GCM and $32$-byte long for AES-256-GCM.

5. Output $(\mathsf{mk}_\N = \mathsf{mk}_\C\oplus\mathsf{mk},\mathsf{sk}_\N = \mathsf{sk}_\C\oplus\mathsf{sk}).$

The output is given to $\N$.
