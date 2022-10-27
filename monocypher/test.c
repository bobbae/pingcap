#include "monocypher.h"
//#include "sha512.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void main()
{
	uint8_t secret_key[32];
	uint8_t public_key[32];
	uint8_t signature_public_key[32];
	uint8_t peer_secret_key[32];
	uint8_t peer_public_key[32];
	uint8_t shared_secret[32];
	uint8_t signature[64];
	uint8_t peer_shared_secret[32];
	uint8_t nonce[24];	/* Use only once per key       */
	uint8_t unique_id[13] = "My unique ID";	/* Unique ID that can be signed */
	uint8_t plain_text[12] = "Lorem ipsum";	/* Secret message */
	uint8_t mac[16];	/* Message authentication code */
	uint8_t cipher_text[12];	/* Encrypted message */
	int i;

	//arc4random_buf(key,   32);
	//arc4random_buf(nonce, 24);

	//Fill in bogus secret key for demo
	for (i = 0; i < 32; i++) {
		secret_key[i] = i & 0xff;	// terrible "secret" key for demo only
	}

	printf("secret_key\n");
	for (i = 0; i < 32; i++) {
		printf("%x ", secret_key[i]);
	}
	printf("\n");

	//Fill in bogus Peer's secret key
	for (i = 0; i < 32; i++) {
		peer_secret_key[i] = (i + 42) & 0xff;	// terrible "secret" key for demo only
	}
	printf("\npeer_secret_key\n");
	for (i = 0; i < 32; i++) {
		printf("%x ", peer_secret_key[i]);
	}
	printf("\n");

	//Bogus nonce for demo, used for encryption along with secret_key
	for (i = 0; i < 24; i++) {
		nonce[i] = i & 0xff;
	}
	printf("nonce\n");

	for (i = 0; i < 24; i++) {
		printf("%x ", nonce[i]);
	}
	printf("\n");

	//Create a public key for signing. This is different from the X25519 public key
	crypto_sign_public_key(signature_public_key, secret_key);

	printf("signature_public_key\n");
	for (i = 0; i < 32; i++) {
		printf("%x ", signature_public_key[i]);
	}
	printf("\n");

	//Sign the message with secret_key and signature_public_key. The message (unique_id) is
	//not considered secret. Only verification of the signature for the message is required.
	//Only the holder of secret_key could have signed the message.
	crypto_sign(signature, secret_key, signature_public_key, unique_id,
		    strlen(unique_id));
	printf("signed signature\n");
	for (i = 0; i < 64; i++) {
		printf("%x ", signature[i]);
	}
	printf("\n");

	//Remote is given unique_id message, signature and only the signature_public_key, not secret_key. 
	//On remote machine, using signature_public_key, the message(unique_id) can be checked
	//as signed by the sender holding the secret_key corresponding to the signature_public_key.
	if (crypto_check
	    (signature, signature_public_key, unique_id, strlen(unique_id))) {
		printf("signature is corrupt\n");
	} else {
		//The unique_id signed by the holder of secret_key is verified using signature_public_key.
		printf("signature is verified\n");
	}

	//Demo of Diffie Hellman key exchange PKI via X25519 RFC7748
	//Generate public_key from secret_key
	crypto_x25519_public_key(public_key, secret_key);

	printf("\npublic_key\n");
	for (i = 0; i < 32; i++) {
		printf("%x ", public_key[i]);
	}

	//Remote Peer can generate own peer_public_key from peer's own peer_secret_key
	crypto_x25519_public_key(peer_public_key, peer_secret_key);

	printf("\npeer_public_key\n");
	for (i = 0; i < 32; i++) {
		printf("%x ", peer_public_key[i]);
	}
	printf("\n");

	//Local side compute shared_secret from secret_key and peer_public_key
	crypto_x25519(shared_secret, secret_key, peer_public_key);

	//Remote side compute shared_secret from peer_secret_key and my public_key I sent to him
	crypto_x25519(peer_shared_secret, peer_secret_key, public_key);

	//The same shared_secrets are computed, thus achieving key exchange using public keys only

	printf("shared_secret\n");
	for (i = 0; i < 32; i++) {
		printf("%x ", shared_secret[i]);
	}
	printf("\npeer_shared_secret\n");
	for (i = 0; i < 32; i++) {
		printf("%x ", peer_shared_secret[i]);
	}
	printf("\n");

	crypto_lock(mac, cipher_text, shared_secret, nonce, plain_text,
		    sizeof(plain_text));
	printf("plain_text\n");
	for (i = 0; i < 12; i++) {
		printf("%x ", plain_text[i]);
	}
	printf("\n");

	printf("cipher_text\n");
	for (i = 0; i < 12; i++) {
		printf("%x ", cipher_text[i]);
	}
	printf("\n");

	/* Wipe secrets if they are no longer needed */
	crypto_wipe(plain_text, 12);
	//crypto_wipe(key, 32);

	// We now decrypt the cipher_text using shared_secret

	if (crypto_unlock
	    (plain_text, peer_shared_secret, nonce, mac, cipher_text, 12)) {
		printf("Error: cannot decrypt\n");
		crypto_wipe(secret_key, 32);
	} else {
		printf("Decrypted: %s\n", plain_text);
		crypto_wipe(plain_text, 12);
		crypto_wipe(secret_key, 32);
	}
}
