#include "certificate.h"

#include "nanocbor-helper.h"

#include "cc.h"
#include "os/sys/log.h"
/*-------------------------------------------------------------------------------------------------------------------*/
#define LOG_MODULE "crypto-cert"
#ifdef CRYPTO_SUPPORT_LOG_LEVEL
#define LOG_LEVEL CRYPTO_SUPPORT_LOG_LEVEL
#else
#define LOG_LEVEL LOG_LEVEL_ERR
#endif
/*-------------------------------------------------------------------------------------------------------------------*/
_Static_assert(LINKADDR_SIZE == EUI64_LENGTH, "Invalid linkaddr size");
/*-------------------------------------------------------------------------------------------------------------------*/
/*

CDDL definition of Certificate

Certificate = [
    tbscertificate  : TBSCertificate,
    signature       : bytes,
]

TBSCertificate = [
    serial_number   : uint,
    issuer          : bytes,
    validity        : [notBefore: uint,
                       notAfter: uint],
    subject         : bytes,
    stereotype_tags : StereotypeTags,
    public_key      : bytes,
]

StereotypeTags = [
    device_class    : uint,
]

*/
/*-------------------------------------------------------------------------------------------------------------------*/
int certificate_encode(nanocbor_encoder_t* enc, const certificate_t* certificate)
{
    nanocbor_fmt_array(enc, 2);

    certificate_encode_tbs(enc, certificate);

    nanocbor_put_bstr(enc, (const uint8_t*)&certificate->signature, sizeof(certificate->signature));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int certificate_encode_tbs(nanocbor_encoder_t* enc, const certificate_t* certificate)
{
    nanocbor_fmt_array(enc, 6);
    nanocbor_fmt_uint(enc, certificate->serial_number);
    nanocbor_put_bstr(enc, certificate->issuer, sizeof(certificate->issuer));

    nanocbor_fmt_array(enc, 2);
    nanocbor_fmt_uint(enc, certificate->validity_not_before);
    nanocbor_fmt_uint(enc, certificate->validity_not_after);

    nanocbor_put_bstr(enc, certificate->subject, sizeof(certificate->subject));

    NANOCBOR_CHECK(serialise_stereotype_tags(enc, &certificate->tags));

    nanocbor_put_bstr(enc, (const uint8_t*)&certificate->public_key, sizeof(certificate->public_key));

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
static int certificate_decode_tbs(nanocbor_value_t* dec, certificate_t* certificate)
{
    nanocbor_value_t arr;
    NANOCBOR_CHECK(nanocbor_enter_array(dec, &arr));

    NANOCBOR_CHECK(nanocbor_get_uint32(&arr, &certificate->serial_number));

    NANOCBOR_CHECK(nanocbor_get_bstr_of_len(&arr, certificate->issuer, sizeof(certificate->issuer)));

    nanocbor_value_t validity_arr;
    NANOCBOR_CHECK(nanocbor_enter_array(&arr, &validity_arr));
    NANOCBOR_CHECK(nanocbor_get_uint32(&validity_arr, &certificate->validity_not_before));
    NANOCBOR_CHECK(nanocbor_get_uint32(&validity_arr, &certificate->validity_not_after));

    if (!nanocbor_at_end(&validity_arr))
    {
        return NANOCBOR_ERR_END;
    }

    nanocbor_leave_container(&arr, &validity_arr);

    NANOCBOR_CHECK(nanocbor_get_bstr_of_len(&arr, certificate->subject, sizeof(certificate->subject)));

    NANOCBOR_CHECK(deserialise_stereotype_tags(&arr, &certificate->tags));

    const ecdsa_secp256r1_pubkey_t* public_key;
    NANOCBOR_GET_OBJECT(&arr, &public_key);
    memcpy(&certificate->public_key, public_key, sizeof(certificate->public_key));

    if (!nanocbor_at_end(&arr))
    {
        return NANOCBOR_ERR_END;
    }

    nanocbor_leave_container(dec, &arr);

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
int certificate_decode(nanocbor_value_t* dec, certificate_t* certificate)
{
    nanocbor_value_t arr;
    nanocbor_enter_array(dec, &arr);

    NANOCBOR_CHECK(certificate_decode_tbs(&arr, certificate));

    const ecdsa_secp256r1_sig_t* signature;
    NANOCBOR_GET_OBJECT(&arr, &signature);
    memcpy(&certificate->signature, signature, sizeof(certificate->signature));

    if (!nanocbor_at_end(&arr))
    {
        return NANOCBOR_ERR_END;
    }

    nanocbor_leave_container(dec, &arr);

    return NANOCBOR_OK;
}
/*-------------------------------------------------------------------------------------------------------------------*/
