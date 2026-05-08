#ifndef SECP256K1_VRF_H
#define SECP256K1_VRF_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

int secp256k1_vrf_prove(
    unsigned char proof[81],
    const unsigned char *seckey,
    secp256k1_pubkey *pubkey,
    const void *msg,
    const unsigned int msglen
);

int secp256k1_vrf_verify(
    unsigned char output[32],
    const unsigned char proof[81],
    const unsigned char pk[33],
    const void *msg,
    const unsigned int msglen
);

int secp256k1_vrf_proof_to_hash(
    unsigned char output[32],
    const unsigned char proof[81]
);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_VRF_H */
