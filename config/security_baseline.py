SECURITY_BASELINE = {
    "ike_versions": {
        "preferred": ["IKEv2"],
        "legacy": ["IKEv1"]
    },

    "encryption": {
        "strong": [
            "AES-GCM-16"
        ],
        "acceptable": [
            "AES-CBC",
            "AES-CTR"
        ]
    },

    "minimum_key_length": 128,

    "prf": {
        "strong": [
            "HMAC-SHA2-256",
            "HMAC-SHA2-384",
            "HMAC-SHA2-512"
        ],

        "legacy": [
            "HMAC-MD5",
            "HMAC-SHA1"
        ]
    },

    "dh_groups": {
        "strong": [
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
        ]
    }
}