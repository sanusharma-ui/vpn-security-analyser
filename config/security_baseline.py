SECURITY_BASELINE = {

    "policy_name": "Local passive IPsec crypto policy (not a compliance certification)",

    "ike_versions": {
        "preferred": [
            "IKEv2"
        ],
        "legacy": [
            "IKEv1"
        ]
    },

    "forbidden_exchanges": [
        "Aggressive Mode"
    ],

    "encryption": {
        "preferred": [
            "AES-GCM-16",
            "AES-GCM-12",
            "AES-GCM-8",
            "ChaCha20-Poly1305"
        ],
        "acceptable": [
            "AES-CBC",
            "AES-CTR"
        ],
        "weak": [
            "DES",
            "DES-IV64",
            "3DES",
            "Blowfish",
            "CAST",
            "RC5",
            "IDEA",
            "NULL"
        ]
    },

    "minimum_key_length": 128,
    "preferred_key_length": 256,
    "minimum_nonce_length": 16,  # Length check only; does not establish entropy

    "prf": {
        "preferred": [
            "HMAC-SHA2-256",
            "HMAC-SHA2-384",
            "HMAC-SHA2-512",
            "AES128-XCBC",
            "AES128-CMAC"
        ],
        "legacy": [
            "HMAC-MD5",
            "HMAC-SHA1"
        ]
    },

    "integrity": {
        "preferred": [
            "HMAC-SHA2-256-128",
            "HMAC-SHA2-384-192",
            "HMAC-SHA2-512-256"
        ],
        "legacy": [
            "HMAC-MD5-96",
            "HMAC-SHA1-96"
        ]
    },

    "dh_groups": {
        "preferred": [
            19,  # 256-bit ECP (NIST P-256)
            20,  # 384-bit ECP (NIST P-384)
            21,  # 521-bit ECP (NIST P-521)
            31   # Curve25519
        ],
        "acceptable": [
            14,  # 2048-bit MODP
            15,  # 3072-bit MODP
            16,  # 4096-bit MODP
            17,  # 6144-bit MODP
            18   # 8192-bit MODP
        ],
        "weak": [
            1,   # 768-bit MODP (Logjam vulnerable)
            2,   # 1024-bit MODP (Vulnerable to discrete-log factorization)
            5    # 1536-bit MODP (Below 2048-bit minimum required by NIST)
        ]
    },

    "policy_version": "2026-09-19",
    "compliance": {
        "nist_sp_800_77_rev1": {"assessment": "requires additional evidence"},
        "cnsa_2_0": {"assessment": "not implemented; classical ECDH is not post-quantum"}
    }
}
