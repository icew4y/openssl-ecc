#include <stdio.h>
#include <stdlib.h>
#include <openssl/ecdh.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <time.h>
#include <string.h>

/* Compile: gcc -o OSSLsecp256r1 OSSLsecp256r1.c -lssl -lcrypto -I /usr/local/include -L /usr/local/lib */

#define MILLION 1E6
#define BILLION 1E9

EVP_PKEY *generate_key();
EVP_PKEY *extract_public_key(EVP_PKEY *privKey);
unsigned char *ecdh(EVP_PKEY *pubKey, EVP_PKEY *privKey);
double correct_timing(struct timespec Start, struct timespec End);
unsigned char *ecdh(EVP_PKEY *pubKey, EVP_PKEY *privKey);

int main() {

    float sum_KG = 0;
    float sum_KA = 0;
    float avg_KG = 0;
    float avg_KA = 0;
    const int ITERATIONS = 10000;

    printf("=== OpenSSL implementation of KG and KA using secp256r1 curve ===\n\n");

    //printf(">> Running %d iterations...\n\n", ITERATIONS);

    /* Pre-calculate HN key pair */
    EVP_PKEY *HNPrivKey = generate_key();
    EVP_PKEY *HNPubKey = extract_public_key(HNPrivKey);

    /* Measure timings for key generation and key agreement */
    for (int i = 1; i < ITERATIONS; i++) {
        /* ===== KEY GENERATION START ===== */

        /* Start timer KG */
        struct timespec StartKG, FinishKG;
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &StartKG);

        /* Generate UE key using prime256v1/secp256r1 curve */
        EVP_PKEY *UEPrivKey = generate_key();

        /* Stop timer KG */
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &FinishKG);
        double nseconds_KG = (FinishKG.tv_nsec - StartKG.tv_nsec);

        /* ===== KEY GENERATION FINISH ===== */


        /* ===== KEY AGREEMENT START ===== */

        /* Start timer KA */
        struct timespec StartKA, FinishKA;
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &StartKA);

        /* Derive ephemeral shared key with ECDH */
        unsigned char *shared_key = ecdh(HNPubKey, UEPrivKey);

        /* Stop timer KA */
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &FinishKA);
        double nseconds_KA = (FinishKA.tv_nsec - StartKA.tv_nsec);

        /* ===== KEY AGREEMENT FINISH ===== */

        EVP_PKEY_free(UEPrivKey);
                
        /* Re-calculate the timings if the results are negative */
        if (nseconds_KG < 0) {
            nseconds_KG = correct_timing(StartKG, FinishKG);
        }

        if (nseconds_KA < 0) {
            nseconds_KA = correct_timing(StartKA, FinishKA);
        }

        /* Add the measured times in milliseconds to the cumulative sums */
        sum_KG += (nseconds_KG / MILLION);
        sum_KA += (nseconds_KA / MILLION);
    }

    /* Calculate average measurements, and print results */
    avg_KG = sum_KG / ITERATIONS;
    avg_KA = sum_KA / ITERATIONS;
    printf("Avg KG: %.6f ms\n", avg_KG);
    printf("Avg KA: %.6f ms\n", avg_KA);

    return 0;
}

void error(){
    printf("An error occured\n");
}

/* Generate key 
Ref: https://wiki.openssl.org/index.php/EVP_Key_and_Parameter_Generation */
EVP_PKEY *generate_key(){

    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY *params= NULL;
    EVP_PKEY *key= NULL;

    /* Create context for generating parameters */
    if(!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) error();
    if(!EVP_PKEY_paramgen_init(pctx)) error();

    /* Set paramgen parameters, using prime256v1/secp256r1 */
    if(!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) error();

    /* Generate parameters */
    if(!EVP_PKEY_paramgen(pctx, &params)) error();

    /* Create context for key generation */
    if(params) {
        if(!(kctx = EVP_PKEY_CTX_new(params, NULL))) error();
    } else {
        error();
    };

    /* Generate key*/
    if(!EVP_PKEY_keygen_init(kctx)) error();
    if(!EVP_PKEY_keygen(kctx, &key)) error();

    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_CTX_free(kctx);
    EVP_PKEY_free(params);

    return key;
}

/* Extract public key from private key */
EVP_PKEY *extract_public_key(EVP_PKEY *privKey){
    
    EC_KEY *ecKey; 
    EC_POINT *ecPoint;
    EVP_PKEY *pubKey = EVP_PKEY_new();
    EC_KEY *pubEcKey;

    /* Get EC_KEY from EVP_PKEY */
    if(NULL == (ecKey = EVP_PKEY_get1_EC_KEY(privKey))) error();

    /* Get the EC point for the public key */
    if(NULL == (ecPoint = EC_KEY_get0_public_key(ecKey))) error();

    /* Create EC_KEY with secp256r1/prime256v1 */
    if(NULL == (pubEcKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) error();

    /* Set the EC point for the public key */
    if(!EC_KEY_set_public_key(pubEcKey, ecPoint)) error();

    /* Create EVP_PKEY from EC_KEY */
    if(!EVP_PKEY_set1_EC_KEY(pubKey, pubEcKey)) error();

    EC_KEY_free(ecKey);
    EC_POINT_free(ecPoint);

    return pubKey;
}

/* Derives a shared key from a public key and the peer private key using ECDH 
Ref: https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman */
unsigned char *ecdh(EVP_PKEY *HNpubKey, EVP_PKEY *UEprivKey){

    unsigned char *secret;
    EVP_PKEY_CTX *dctx = NULL;
    size_t secret_len;

    /* Create context for key derivation */
    if(NULL == (dctx = EVP_PKEY_CTX_new(UEprivKey, NULL))) error();

    /* Initialise */
    if(1 != EVP_PKEY_derive_init(dctx)) error();
   
    /* Provide HN's public key */
    if(1 != EVP_PKEY_derive_set_peer(dctx, HNpubKey)) error();
  
    /* Determine buffer length for shared secret */
	if(1 != EVP_PKEY_derive(dctx, NULL, &secret_len)) error();
    
    /* Create buffer */
	if(NULL == (secret = OPENSSL_malloc(secret_len))) error();

    /* Derive shared secret */
	if(1 != (EVP_PKEY_derive(dctx, secret, &secret_len))) error();

    EVP_PKEY_CTX_free(dctx);

	return secret;
}

/* Used to correct instances where the start time and end time are at different seconds,
resulting in a negative number */
double correct_timing(struct timespec Start, struct timespec End) {

    return BILLION + End.tv_nsec-Start.tv_nsec;
}
