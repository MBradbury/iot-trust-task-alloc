from textwrap import wrap
from more_itertools import chunked

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from common.certificate import SignedCertificate

def format_individual(number, size, line_group_size=None, spacing=18):
    if not isinstance(number, bytes):
        number = number.to_bytes(32, 'big')
    hex_num = number.hex().upper()

    wrapped = [f"0x{part}" for part in wrap(hex_num, size)]

    if line_group_size is None:
        return ", ".join(wrapped)
    else:
        chunks = list(chunked(wrapped, line_group_size))
        return f",\n{' '*spacing}".join([", ".join(chunk) for chunk in chunks])

def contiking_format_our_privkey(private_key, our_deterministic_string=None):
    public_key_nums = private_key.public_key().public_numbers()
    private_value = private_key.private_numbers().private_value

    private_key_hex_formatted = format_individual(private_value, 2, line_group_size=8, spacing=11)

    return f"""const ecdsa_secp256r1_privkey_t our_privkey = {{ // {our_deterministic_string}
    .k = {{ {private_key_hex_formatted} }},
}};"""

def contiking_format_certificate(cert: SignedCertificate, variable_name, deterministic_string=None):
    issuer_formatted = format_individual(cert.issuer, 2)
    subject_formatted = format_individual(cert.subject, 2)

    public_key_nums_x_formatted = format_individual(cert.public_key[0:32], 2, line_group_size=8, spacing=23)
    public_key_nums_y_formatted = format_individual(cert.public_key[32:64], 2, line_group_size=8, spacing=23)

    signature_nums_r_formatted = format_individual(cert.signature[0:32], 2, line_group_size=8, spacing=23)
    signature_nums_s_formatted = format_individual(cert.signature[32:64], 2, line_group_size=8, spacing=23)

    return f"""const certificate_t {variable_name} = {{ // {deterministic_string}
            .serial_number = {cert.serial_number},

            .issuer = {{ {issuer_formatted} }},
            .subject = {{ {subject_formatted} }},

            .validity_not_before = {cert.validity_from},
            .validity_not_after = {cert.validity_to},

            .tags = {{
                .device_class = {cert.stereotype_tags.device_class.cname()},
            }},

            .public_key = {{
                .x = {{ {public_key_nums_x_formatted} }},
                .y = {{ {public_key_nums_y_formatted} }}
            }},

            .signature = {{
                .r = {{ {signature_nums_r_formatted} }},
                .s = {{ {signature_nums_s_formatted} }}
            }} 
}};"""
