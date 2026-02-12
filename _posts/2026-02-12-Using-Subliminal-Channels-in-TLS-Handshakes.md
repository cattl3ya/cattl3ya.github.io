---
title: "Using Subliminal Channels in TLS Handshakes as a C2 Method"
date: 2026-02-12 00:00:00 +/-0000
categories: [Guides]
tags: []     # TAG names should always be lowercase
---

### Introduction
Did you know that it's possible to hide a message inside a digital signature? And that a signature containing a message will pass validation checks and be indistinguishable from a signature that does not contain a message? And that any observer who sees the signature will not only be unable to read the message, but will have no idea that it even exists?

That is what a *subliminal channel* can do. Now, think about all of the digitally signed data that's constantly being shared over the internet: x.509 certificates, TLS connections, DKIM email headers, linux packages, kerberos tickets, cryptocurrency transactions, and so on. If it's something that uses a signature algorithm based on DSA or EcDSA, it could be used to send messages over a subliminal channel. The way using a subliminal channel works, in a general protocol, is:
- Alice and Bob are going to prison, and want to be able to communicate secretly. They share a secret key before being incarcerated, however, Wallis the warden will only allow them to exchange plaintext messages that he has inspected. 
- Alice sends a signed plaintext message to Bob through Wallis.
- Wallis inspects the message and verifies Alice's signature. He finds nothing suspect about either the message or the signature and sends it to Bob.
- Bob checks the signature and sees that it's valid, confirming that Wallis hasn't changed anything. He discards the plaintext message and uses the secret key shared earlier with Alice to extract the subliminal message from the signature. 
Alice and Bob have achieved communication through the subliminal channel, while Wallis is unable to tell that anything is happening.

How is this different from other methods of hiding messages inside data? The subliminal channel is distinguished from *steganography* because we're still using a key pair, performing operations on a plaintext message, and creating a valid cryptographic signature. It's closer to a form of *obfuscation*, because the data you're hiding goes through some mathematical operations to hide it inside the signature, but the obfuscation is invisible. You can tell the difference right away between obfuscated C code and plain C code. But a signature containing a subliminal message is indistinguishable from one that does not, and passes the same verification checks. 

When I learned about this, I thought it was a fascinating concept: hiding undetectable messages in plain sight. You could be handcuffed to a chair, being asked some difficult questions, and because you were clever and used subliminal channels you could say "I don't know anything, all the signatures are normal, you can verify them with the key yourself". Thinking about it from the hacking perspective, there could be a use for for data exfiltration, command and control, and payload delivery. Then I thought about HTTPS connections and TLS. TLS handshakes are everywhere, and they exchange digital signatures. What if I could set up a subliminal channel in the signatures used during the TLS handshake? To an observer, it'd just look like any one of the thousands of TLS handshakes that occur over the wire. The secret message is exchanged during the handshake, and whatever data is sent afterwards is irrelevant. Even if someone looked closely at the handshake data, all they'd see is a perfectly normal handshake with valid signatures. I thought it would be fun to pursue this idea, and decided to write a C2 program that would exchange subliminal messages over TLSv1.3 with EdDSA signatures. 

That's where I got the idea for this paper. I'm assuming only some basic knowledge of network protocols and cryptographic concepts on the part of the reader, so I will first explain the specific case of how subliminal channels work in EdDSA. Then, I will cover some details of the TLSv1.3 handshake, where subliminal channels occur in it, and how they can be used. With this background context established, I'll show how I patched the WolfSSL library to use subliminal channels, and how my C2 server and client work. I'll conclude with an examination of what the C2 traffic looks like in a packet capture, the advantages and disadvantages of this technique, and some closing thoughts. 

If you're already curious and want to experiment with it yourself now, can skip to the build guide at the start of the Implementation section. If you want to see what it looks like in action and the key points, skip to the Results and Conclusion sections. 

### Background: Subliminal Channels in EdDSA
Gustavus Simmons invented the concept of a subliminal channel and demonstrated their existence in the Digital Signature Algorithm (DSA). The general idea is that DSA has parameters that must be set with random information. By manipulating this random value, you can affect the value of the signature. The signature remains valid, but contains information related to value used in its generation. The channel is present algorithms that calculate signatures similarly to DSA, such as Elliptic-curve DSA (EcDSA), and Edwards-curve DSA (EdDSA). 

After doing some more research on EdDSA, it turned out that my idea wasn't new, and I found the paper "A Subliminal Channel in EdDSA: Information Leakage with High-Speed Signatures" by Hartl, Annessi, and Zseby [(link)](https://doi.org/10.1145/3139923.3139925) . They described the subliminal channel in EdDSA and tested some methods of using it, including in TLS handshakes. This paper was very helpful for figuring out the math behind implementing the subliminal channel.

So how does the EdDSA subliminal channel work? First, we have to look at what an EdDSA signature actually is:
1. The signature for message M is in the form of `(R, S)`. R and S are each 32 bytes long.
2. `R = rB`, where `r` is a nonce value and `B` is a point on an elliptic curve. The important thing here is that our subliminal data will go into `r`, which in turn affects the value of `R`. 
3. `S = r + H(RAM)a mod L`, which will be important later in decoding the subliminal message. For now, it will suffice to say that `H(RAM)` refers to a hash of the message, public key, and the `R` value above.

The subliminal channel exists through our ability to determine `R` by setting the nonce value `r` to a value of our choice. Now, there's a lot of considerations that go into how nonce values are chosen, how insecure nonces can lead to leaking private keys or data, deterministic vs random nonce values, and so on. To keep things simple, in the standard EdDSA implementation, the nonce is generated deterministically by hashing some bits of the private key along with the message. But the nonce doesn't *need* to be generated this way, it's just more secure when it is. You can use any value you want, and it will result in a valid signature. `r` is implemented as 32 bytes, so our subliminal messages can be just short of 32 bytes long. This is because...well, as the paper written by people much better at math than me explains it: *"Since information can only be encoded in the residue class modulo L, the subliminal channel has a theoretical bandwidth of log2 L bits per signature. For Ed25519 this corresponds to a bandwidth of 252 bits per signature."* Practically speaking, it means we'll be sending 31 bytes over the subliminal channel. 

After the signature `(R,S)` is created, given the definitions above, you can see that we can solve for the nonce value `r`: `r = S − H (R, A, M)a mod L`. The recipient will have the message `M`, the public key `A`, the signature component `R`, the signature component `S`, and the value `mod L`. The only thing missing is the value derived from the private key, `a`, which can be exchanged using either out-of-band techniques, or by using the *narrowband* subliminal channel. 

Yes, there is another way to use subliminal channels in EdDSA that does not require sharing a key. It can only send a few bits at a time, so is called the *narrowband channel*, while the channel we were just discussing that can send 252 bits is the *broadband channel*. 

The narrowband channel hides data in the signature component `R`, through generating random `r` values until one is found that generates an `R` value that contains the data you wanted to transmit. The implementation looks like this: 
- Alice and Bob agree that the last `b` bits of the signature component `R` contains subliminal data. In this example, they agree the last 4 bits are the message, so `b = 4`.
- Alice wants to send the message `0101`, so she generates random `r` values until she finds one that generates an `R` value ending in `0101`. She has to test `2^b` values on average until she finds a suitable nonce, so she'll have had to run the signature algorithm about 2^4 or 16 times. 
- Bob receives the message `M` and the signature `(R,S)`. He doesn't need to take any special steps to decode the subliminal message, as it's contained right there in the last 4 bits of R: `0101`.
- Alice and Bob repeat the process, sending 4 bits at a time. Any observer will not notice anything amiss, as all the signatures are valid. Eventually Bob reconstructs the message after concatenating all the 4 bit pieces together.

For my implementation, I'll use the narrowband channel to send over a private key, and then use the broadband channel to communicate 31 bytes, or 248 bits of data at a time.

### Background: TLS 1.3 handshakes
We now understand how we can embed subliminal data in EdDSA signatures, either a few bits at a time or in 252 bit chunks. Let's look at how we can apply this to the TLS handshake.

The basic structure of a TLS 1.3 handshake is:
- Client sends `ClientHello`
- Server sends `ServerHello`
- Server sends `EncryptedExtensions`, `Certificate`, `CertificateVerify`, and `Finished` messages. If mutual TLS is requested, the server will also send a `CertificateRequest` message.
- Client verifies the certificate, generates session keys, and sends the `Finished` message. If the `CertificateRequest` message was sent by the server, the client will send its own `Certificate` and `CertificateVerify` before the `Finished` message.

The key part we're interested in are the `CertificateVerify` messages.

So what's special about the `CertificateVerify` message? It's defined in the RFC as containing a 2 byte value specifying which algorithm is used (Ed25519 in our case), and a digital signature (a 64 byte EdDSA signature here). The data used to generate this signature is a hash of all the messages sent so far in the handshake. This is perfect for our needs because the `ClientHello` and `ServerHello` messages each contain a 32 byte random number. Therefore each handshake hash will be unique, and therefore each `CertificateVerify` signature will be unique. This is important because if every message was the same, but the signatures were different (remember, EdDSA signatures are *deterministic*, they should output the same signature for the same message), it'd be easy to notice something unusual was going on.

Our modified `CertificateVerify` message containing subliminal data is therefore indistinguishable from a normal `CertificateVerify` message. Additionally, it is also encrypted, as TLS 1.3 encrypts everything after the `ClientHello` and `ServerHello` message, giving another layer of secrecy.

There's been some prior work by others with the idea of hiding data at various points within TLS handshakes. These generally take the approach of using fields within TLS messages or the certificates themselves to exchange data. For example, hiding data inside the `ClientHello` [message](https://medium.com/@haarlems/tls-data-exfiltration-smuggling-bytes-with-clienthello-93b9449d9005), using the x.509 SubjectKeyIdentifier [field](https://www.youtube.com/watch?v=y38-xLf4iEo) to hide data, using the X.509 SubjectAlternativeName [field](https://github.com/sourcefrenchy/certexfil), or the TLS Server Name Indication [field](https://www.mnemonic.io/resources/blog/introducing-snicat). However, the subliminal channel method has two key things that distinguish it:
1. The other methods can be detected by inspecting the plaintext `ClientHello` messages, or examining the certificates and seeing that unusual data is present in certain fields compared to normal traffic. The subliminal channel is hard to detect for the reasons explained above: anyone examining the traffic will see normal TLS handshakes occurring with the expected values in the right fields, valid certificates that don't contain any extra data, and that everything has been signed with a valid, verifiable signature.
2. TLS inspection will block our channel, but will not compromise it. Because the TLS inspection proxy creates a new TLS connection and doesn't forward our signed `CertificateVerify` message, the subliminal data in the signature won't be passed through the proxy. However, anyone inspecting the messages that the client and server tried to exchange will be unable to tell what is going on, as they will only see an attempt to do a mutual TLS handshake.

### Implementation
With the background out of the way, I'll now explain how I implemented this technique as a proof-of-concept. If you want to skip the details, go to the Results section. If you want to jump into playing with the demo, check out the github page [here](https://github.com/cattl3ya/tls-subliminal-channel.git) follow this build guide:

#### Build Instructions:
1. `git clone https://github.com/cattl3ya/tls-subliminal-channel.git`
2. `git clone https://github.com/wolfSSL/wolfssl.git`
3. Copy the files from `./tls-subliminal-channel/wolfssl-5.8.4/` to `./wolfssl-5.8.4/` to overwrite ed25519.c, ed25519.h, tls13.c, and libwolfssl_sources.h
4. Build WolfSSL with the options `./configure --disable-shared --enable-opensslall --enable-ed25519 --enable-certgen --enable-opensslextra --enable-savecert --enable-keylog-export` and build with `make`
5. Either edit the `WOLFSSL_LIB = ./wolfssl-5.8.4/lib/libwolfssl.a` in the makefile to point to the location of your patched WolfSSL library, or copy the patched library into the expected directory with `mkdir ./tls-subliminal-channel/wolfssl-5.8.4/lib && cp ./wolfssl-5.8.4/src/.libs/libwolfssl.a ./tls-subliminal-channel/wolfssl-5.8.4/lib`
6. Run `make certs` to generate the certificates
7. Run `make` to compile the client and server
8. If you want to be able to decrypt the traffic, set `export SSLKEYLOGFILE=./ssl_key_log.txt` in your terminal
9. Start the server and client programs

#### Initial Planning
In general, we have to accomplish two things to implement the subliminal channel:
1. Override the nonce value `r` generated during EdDSA signing.
2. Access the signature data in the `CertificateVerify` messages so we can either access the important bits of `R` for the narrowband channel or decode the signature to recover `r` for the broadband channel.

Objective 1 requires us to patch the library function that implements the core EdDSA signing algorithm, and objective 2 requires us to hook into whatever library function implements the TLS handshake, as normally you would never need to care about the `CertificateVerify` signature beyond whether it's valid or not. 

Our problem is that writing a program to do TLS handshakes will typically use a crypto library like OpenSSL or the Windows SChannel libraries to handle everything, and crypto libraries don't allow users to mess around with the signing algorithm or the internal details of the TLS handshake. So we'll need to make a patch.

There's a few methods to go about this:
1. Write our server/client programs, and implement EdDSA and TLS from scratch.
2. On Windows, do something like IAT hooking to intercept the library calls that create the TLS connection and EdDSA signatures and use our own code. On Linux, we could use LD_PRELOAD to hook the OpenSSL functions and override what we want.
3. Find a small crypto library that implements TLS and EdDSA, patch it, build it, and statically link it to our server and client programs. 

Option 3 sounded like the simplest and easiest way to go about it. I chose the WolfSSL library because it was small, well-documented, and supported TLSv1.3 with EdDSA. The total size of my client and server programs after static linking were around 1.5MB each, which was pretty nice compared to the size you'd get with something like statically linking OpenSSL.

### Patching WolfSSL - Overriding the EdDSA nonce
Our goal is to:
1. Be able to set the nonce in the EdDSA signing algorithm to arbitrary values.
2. Be able to access the data in the `CertificateVerify` message.

Therefore, there's two places we need to patch WolfSSL:
1. The EdDSA signing algorithm itself.
2. Where the `CertificateVerify` message is processed during the TLS handshake.

We'll begin with patching the signing algorithm.

After looking through the WolfSSL source, the EdDSA signing algorithm is implemented in `wolfcrypt/src/ed22519.c`, in the function `wc_ed25519_sign_msg_ex`. The WolfSSL code is well documented, and it's easy to see where our patch needs to go around line 480:
```c
/* step 1: create nonce to use where nonce is r in
r = H(h_b, ... ,h_2b-1,M) */
ret = ed25519_hash(key, key->k, ED25519_KEY_SIZE, az);
if (ret != 0)
	return ret;
/* apply clamp */
az[0] &= 248;
az[31] &= 63; /* same than az[31] &= 127 because of az[31] |= 64 */
az[31] |= 64;
```
(I'm leaving out various `#ifdef` statements related to different WolfSSL build options for clarity.)
```c
sc_reduce(nonce);
/* step 2: computing R = rB where rB is the scalar multiplication of
r and B */
ge_scalarmult_base(&R,nonce);
ge_p3_tobytes(out,&R);
```
The `nonce` value is the `r` value we discussed above, so we see here where the nonce value is generated. Let's add in our patch to override the value of `nonce`.
At the top of the source file, we'll define some global variables to set the nonce and control whether we're using the narrowband or broadband subliminal channel.
```c
//PATCH CODE
//variables used for overriding the nonce value in the signing function
unsigned char g_override_nonce[64] = {0};
int g_narrowband_override_nonce = 0;
int g_broadband_override_nonce = 0;
unsigned char g_narrowband_target;
//END PATCH CODE
```
Then, in between `sc_reduce(nonce);` and the start of step two, we'll put in our patch:
```c
//PATCH CODE
//narrowband channel
if (g_narrowband_override_nonce == 1){
	//initialize an RNG and temporary variables
	WC_RNG rng;
	wc_InitRng(&rng);
	ge_p3 R2;
	unsigned char t_out[32];
	unsigned char temp_nonce[64];
	unsigned char reduced_nonce[64];
	int found = 0;
	while (found == 0){
		//generate a random nonce value
		wc_RNG_GenerateBlock(&rng, temp_nonce, 64);
		XMEMCPY(reduced_nonce, temp_nonce, 64);
		sc_reduce(reduced_nonce);
		ge_scalarmult_base(&R2, reduced_nonce);
		ge_p3_tobytes(t_out, &R2);
		//check if the last 4 bits of R will be equal to the value we wanted
		if((t_out[31] & 0x0F) == g_narrowband_target) {
			found = 1;
		}
	}
	wc_FreeRng(&rng);
	//copy the nonce that created the R value with our target
	XMEMCPY(nonce, reduced_nonce, 32);
}
 
//broadband channel
if (g_broadband_override_nonce == 1){
	//overwrite the nonce with our specified one
	XMEMCPY(nonce, g_override_nonce, 64);
	sc_reduce(nonce);
}
//END PATCH CODE
```
The patch is not very complex. For the narrowband channel, we just need to test random nonces until we find one that results in an `R` value with the last 4 bits equal to our subliminal message. The broadband channel is even simpler, we can just overwrite the entire nonce with our subliminal message. Then we just need to add a function that we can call from our client/server program to set the control variables. I put it at the bottom of the file:
```c
//PATCH CODE
WOLFSSL_API int wc_ed25519_SetNonceOverride(unsigned char* nonce, int len, char type, unsigned char target){
//set either narrowband, broadband, or skip nonce override
	if (type == 'n'){
		g_narrowband_override_nonce = 1;
		g_broadband_override_nonce = 0;
		g_narrowband_target = target;
	}else if (type == 'b'){
		g_broadband_override_nonce = 1;
		g_narrowband_override_nonce = 0;
		XMEMCPY(g_override_nonce, nonce, len);
	}else if (type == 'x'){
		g_broadband_override_nonce = 0;
		g_narrowband_override_nonce = 0;
	}
	return 0;
}
//END PATCH CODE
```
and add the function to the `ed22519.h` file
```c
//PATCH CODE
int wc_ed25519_SetNonceOverride(unsigned char* nonce, int len, char type, unsigned char target);
//END PATCH CODE
```

### Patching WolfSSL - Extracting the CertificateVerify Signature
Patching the EdDSA signing function was pretty simple. Now we have to find out a way to patch the TLS handshake function to be able to read data from the `CertificateVerify` messages. These functions aren't exposed to the user, because there's ordinarily no reason to need to access these values: they either pass the validation check and can be discarded, or they fail the validation check and a TLS handshake error gets returned. WolfSSL handles the TLS 1.3 handshake in the `src/tls13.c` file. Inside, we find the conveniently named `DoTls13CertificateVerify` function, where the CertificateVerify message of the handshake is parsed and validated.

What we need to do here is:
1. For the narrowband channel, we only need to copy the last 4 bits of the signature's `R` value.
2. For the broadband channel, we need to copy the entire `CertificateVerify` message. Remember, we can't solve for `r` without the message, message length, public key, signature, and private key.

Because we need to get data *out* rather than *in*, we'll define a few external variables that we can then access in our client/server program. `tls13.c` includes the `wolfssl/wolfcrypt/libwolfssl_sources.h` header, so we'll declare our variables there:
```c
//PATCH CODE
//struct to hold the CertificateVerify data
struct bb_subliminal_data {
	unsigned char signature[64];
	unsigned char public_key[64];
	unsigned char* message;
	unsigned int message_length;
};
extern struct bb_subliminal_data *g_subliminal_data;
//nb_output is the last 4 bits of the R value of the CertificateVerify signature
extern unsigned char nb_output;
//g_subliminal_type is for controlling our patch in tls13.c
//0 sets the narrowband channel, 1 sets the broadband channel
extern unsigned char g_subliminal_type;
//END PATCH CODE
```
then define them at the start of `tls13.c`
```c
//PATCH CODE
//initialize our external variables
unsigned char nb_output = 0x00;
unsigned char g_subliminal_type = 2; // 0 = narrowband, 1 = broadband, any other value = off
struct bb_subliminal_data *g_subliminal_data = {0};
//END PATCH CODE
```
Now we'll go through the `DoTls13CertificateVerify` function until we come to the case where EdDSA signatures are verified (around line 10640) by accessing the `CertificateVerify` data in the function's arguments:
```c
#ifdef HAVE_ED25519
if ((ssl->options.peerSigAlgo == ed25519_sa_algo) 
	&& (ssl->peerEd25519KeyPresent)) {
	WOLFSSL_MSG("Doing ED25519 peer cert verify");
```
and add our patch
```c
//PATCH CODE
//using narrowband channel, set nb_output to the last 4 bits of the signature's R value
if (g_subliminal_type == 0){
	nb_output = sig[31] & 0x0F;
}
//using broadband channel
if (g_subliminal_type == 1) {
	//allocate struct to hold the certificateverify data
	if (g_subliminal_data == NULL) {
		g_subliminal_data = (struct bb_subliminal_data*)malloc(sizeof(struct bb_subliminal_data));
		if (g_subliminal_data == NULL) 
			return MEMORY_E;
		memset(g_subliminal_data, 0, sizeof(struct bb_subliminal_data));
	}
	//validate sizes
	if (args->sigSz > 64) 
		return BUFFER_E;
	if (args->sigDataSz == 0 || sig == NULL || ssl->peerEd25519Key == NULL) {
		return BAD_FUNC_ARG;
	}
	//copy data
	memcpy(g_subliminal_data->signature, sig, args->sigSz);
	memcpy(g_subliminal_data->public_key, ssl->peerEd25519Key, 32);
	if (g_subliminal_data->message != NULL) {
		free(g_subliminal_data->message);
	}
	g_subliminal_data->message = (unsigned char*)malloc(args->sigDataSz);
	if (g_subliminal_data->message == NULL) 
		return MEMORY_E;
	memcpy(g_subliminal_data->message, args->sigData, args->sigDataSz);
	g_subliminal_data->message_length = args->sigDataSz;
}
//END PATCH CODE
```
Again, the patch isn't very complicated. The only trick is in allocating our struct and copying the correct values before the signature is verified.

And that's it for our patch. We just need to build our patched WolfSSL library for static linking after we have our client and server.

### C2 Server and Client
After patching WolfSSL, I wrote a simple server and client program in C. There's nothing particularly special about the code, so for brevity I won't include any code here (you can always take a look at it on github), but will give a general overview of how the programs work.

#### Server
1. Has a transmit (tx) and receive (rx) buffer. Commands for the client are read from `stdin`, formatted, and copied into the tx buffer.
2. If the tx buffer contains a complete message, the EdDSA nonce is overridden (either on the broadband or narrowband channel) and the server waits for a connection. If there is no message, the nonce is not overridden (i.e. it proceeds according to the specified implementation) and the server waits for a connection.
3. If a client connects, the data in the client's `CertificateVerify` message is copied to the rx buffer, a simple HTTP response is sent, and the connection is closed.
4. The rx buffer is checked for any complete messages. If there are, the message is output and the rx buffer cleared.
5. GOTO (1)

Because the client may or may not actually be using the subliminal channel, the rx buffer will fill up with essentially random bytes. Therefore I implemented a small protocol of command sequences. The byte sequence `A0A0` is a command start, `F0F1` is a command end. They're defined at the start of the c files if you're interested in playing with them. With 4 bytes, it's unlikely that these sequences will appear randomly.

#### Client:
1. Has a tx and rx buffer. The rx buffer is checked for any command sequences. If so, the commands are executed and `stdout` read into the tx buffer.
2. If the tx buffer isn't empty, override the EdDSA nonce, connect to the server, and send an HTTP request. If it is empty, wait x seconds and connect to the server. 
3. Copy the data in the server's `CertificateVerify` message into the rx buffer and receive the HTTP response.
4. GOTO (1)

### Results
Now we're all ready to go. This is what it looks like to execute some commands over the narrowband channel: 

![](assets/img/narrowband_c2.png)

And over the broadband channel:

![](assets/img/broadband_c2.png)

You can notice the difference in speed between the narrowband and broadband channels. To do a simple `whoami` and get the reply required 130 handshakes over the narrowband channel. Running something with a fair amount of output, like `ls`, required 290 handshakes to transmit the data. In comparison, the broadband channel can handle `ls` in 10 handshakes.

So what does it look like over the wire?
It looks like...

![](assets/img/wshark_1.png)

...a ton of TLS handshakes that are all almost exactly the same. We see the hello messages, then the encrypted parts of the handshake, then a small bit of encrypted data being exchanged.

Let's start another packet capture, this time dumping the TLS session keys to a log so we can decrypt the traffic:

![](assets/img/wshark_2.png)

With the decrypted traffic, there's still nothing very suspicious. We have a mutual certificate exchange, and then an HTTP request and response with nothing in it. There's nothing to give away that we were actually running commands on the client and receiving a response.

Let's take a look at when the client received the `whoami` command over the broadband channel:

![](assets/img/whoami.png)

We see the signature of the server's `CertificateVerify` message, that it passed the validation checks, and that it successfully decoded to our command sequence and executed `whoami`. 
Let's go back and search for that signature so we can look at the packet where it happens:

![](assets/img/whoami_packet.png)

And there it is! We see the server sending an apparently plain old `CertifcateVerify` message. Anyone looking at this would have no idea the signature actually contains the subliminal data `whoami`.
### Conclusions
So we've successfully run some commands by using subliminal channels in TLS handshakes. I didn't think it'd be so interesting to look at packets where apparently nothing is happening.

The advantages:
1. No way to tell that we're sending subliminal messages. Well, almost. There's a lot of research on trying to prevent subliminal channels, so anyone who wanted to shut down this possibility could insist on using algorithms or implementations that mitigate subliminal channels. 
2. The traffic mostly consists of TLS handshakes, so there are no large encrypted messages being sent that might arouse suspicion.
3. All messages, signatures, and certificates are valid without any unusual headers or data present.

The disadvantages:
1. Extremely noisy narrowband channel that needs hundred of handshakes to exchange short messages. Doing nothing but a TLS handshake and then closing the connection over and over for hundreds of times is definitely unusual. The broadband channel isn't too noisy though, if you can handle the private key exchange. Doing 10 or 20 TLS handshakes spaced out over the course of a few hours might go unnoticed.
2. TLS inspection breaks the channel because it doesn't send the original `CertificateVerify` messages. On the plus side, it doesn't compromise the channel because there's apparently nothing to see besides a self-signed certificate, `GET / HTTP1.1`, and `HTTP/1.1 200 OK`.
3. If someone finds the client and reverse engineers it, it'll be pretty obvious (especially after they've read this paper) what's happening.

 This would also make a tricky CTF puzzle: hide the flag in one of the signatures, then give people a private EdDSA key along with a pcap file that contains a single TLS handshake. 
 
I had a lot of fun working on this project and going deep into TLS, digital signatures, and ways of hiding data in plain sight. I hope you learned something as well, and will maybe be inspired to experiment with subliminal channels somewhere else in an interesting way.