SECURITY_BASELINE = {

    "policy_name": "Default IPsec Security Baseline",

    "ike_versions": {

        "preferred": [
            "IKEv2"
        ],

        "legacy": [
            "IKEv1"
        ]
    },

    "encryption": {

        "preferred": [
            "AES-GCM-16"
        ],

        "acceptable": [
            "AES-CBC",
            "AES-CTR"
        ],

        "weak": [
            "DES",
            "3DES",
            "NULL"
        ]
    },

    "minimum_key_length": 128,

    "preferred_key_length": 256,

    "prf": {

        "preferred": [
            "HMAC-SHA2-256",
            "HMAC-SHA2-384",
            "HMAC-SHA2-512"
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
            19,
            20,
            21
        ],

        "acceptable": [
            14,
            15,
            16,
            17,
            18
        ],

        "weak": [
            1,
            2,
            5
        ]
    }
}