// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Defines [`BitStrength`], [`KESettings`] enums and [`assert_compliance`] method.

use crate::tunnel::tls::security::BitStrength::{Bits128, Bits192, Bits256};
use crate::tunnel::tls::security::KESettings::{Classical, Hybrid, QuantumSafe};

use pb::TLSConfigurationError;

use pb_api::compliance::{
    ClassicalAlgoChoice, HybridAlgoChoice, NISTSecurityStrengthBits, QuantumSafeAlgoChoice,
};
use pb_api::tls::TLSv13Config;

/// Represents the AES bit size equivalent hardness of breaking an algorithm.
#[derive(PartialEq, PartialOrd, Eq)]
enum BitStrength {
    Bits128 = 128, // AES-128
    Bits192 = 192, // AES-192
    Bits256 = 256, // AES-256
}

/// Implements [`From`] for [`BitStrength`].
impl From<NISTSecurityStrengthBits> for BitStrength {
    fn from(nist_bit_strength: NISTSecurityStrengthBits) -> Self {
        match nist_bit_strength {
            NISTSecurityStrengthBits::BIT_STRENGTH_AT_LEAST_128 => Bits128,
            NISTSecurityStrengthBits::BIT_STRENGTH_AT_LEAST_192 => Bits192,
            NISTSecurityStrengthBits::BIT_STRENGTH_AT_LEAST_256 => Bits256,
        }
    }
}

/// A cryptographic algorithm: is it safe to attack from quantum computer, unsafe, or a hybrid.
enum KESettings {
    Classical(BitStrength),
    QuantumSafe(BitStrength),
    Hybrid(BitStrength),
}

/// Implements [`TryFrom`] for [`KESettings`].
impl TryFrom<&str> for KESettings {
    type Error = crate::Error;

    fn try_from(alg: &str) -> crate::Result<Self> {
        let ke_setting: Option<KESettings> = match alg {
            "brainpoolP256r1" => Some(Classical(Bits128)),
            "brainpoolP384r1" => Some(Classical(Bits192)),
            "brainpoolP512r1" => Some(Classical(Bits256)),

            "sect283k1" => Some(Classical(Bits128)),
            "sect283r1" => Some(Classical(Bits128)),

            "sect409k1" => Some(Classical(Bits192)),
            "sect409r1" => Some(Classical(Bits192)),

            "sect571k1" => Some(Classical(Bits256)),
            "sect571r1" => Some(Classical(Bits256)),

            "X25519" => Some(Classical(Bits128)),
            "prime256v1" => Some(Classical(Bits128)),

            // Actually it's 224-bit security.
            // See <https://github.com/openssl/openssl/blob/master/include/crypto/ecx.h#L37C11-L37C29>
            "X448" => Some(Classical(Bits192)),

            "secp256k1" => Some(Classical(Bits128)),
            "secp384r1" => Some(Classical(Bits192)),
            "secp521r1" => Some(Classical(Bits256)),

            // See <https://github.com/open-quantum-safe/oqs-provider/blob/main/oqsprov/oqsprov.c#L369>
            "frodo640aes" => Some(QuantumSafe(Bits128)),
            "p256_frodo640aes" => Some(Hybrid(Bits128)),
            "x25519_frodo640aes" => Some(Hybrid(Bits128)),

            "frodo640shake" => Some(QuantumSafe(Bits128)),
            "p256_frodo640shake" => Some(Hybrid(Bits128)),
            "x25519_frodo640shake" => Some(Hybrid(Bits128)),

            "frodo976aes" => Some(QuantumSafe(Bits192)),
            "p384_frodo976aes" => Some(Hybrid(Bits192)),
            "x448_frodo976aes" => Some(Hybrid(Bits192)),

            "frodo976shake" => Some(QuantumSafe(Bits192)),
            "p384_frodo976shake" => Some(Hybrid(Bits192)),
            "x448_frodo976shake" => Some(Hybrid(Bits192)),

            "frodo1344aes" => Some(QuantumSafe(Bits256)),
            "p521_frodo1344aes" => Some(Hybrid(Bits256)),
            "frodo1344shake" => Some(QuantumSafe(Bits256)),
            "p521_frodo1344shake" => Some(Hybrid(Bits256)),

            "kyber512" => Some(QuantumSafe(Bits128)),
            "p256_kyber512" => Some(Hybrid(Bits128)),
            "x25519_kyber512" => Some(Hybrid(Bits128)),

            "kyber768" => Some(QuantumSafe(Bits192)),
            "p384_kyber768" => Some(Hybrid(Bits192)),
            "x448_kyber768" => Some(Hybrid(Bits192)),
            "x25519_kyber768" => Some(Hybrid(Bits128)),
            "p256_kyber768" => Some(Hybrid(Bits128)),

            "kyber1024" => Some(QuantumSafe(Bits256)),
            "p521_kyber1024" => Some(Hybrid(Bits256)),

            "bikel1" => Some(QuantumSafe(Bits128)),
            "p256_bikel1" => Some(Hybrid(Bits128)),
            "x25519_bikel1" => Some(Hybrid(Bits128)),

            "bikel3" => Some(QuantumSafe(Bits192)),
            "p384_bikel3" => Some(Hybrid(Bits192)),
            "x448_bikel3" => Some(Hybrid(Bits192)),

            "bikel5" => Some(QuantumSafe(Bits256)),
            "p521_bikel5" => Some(Hybrid(Bits256)),

            "hqc128" => Some(QuantumSafe(Bits128)),
            "p256_hqc128" => Some(Hybrid(Bits128)),
            "x25519_hqc128" => Some(Hybrid(Bits128)),

            "hqc192" => Some(QuantumSafe(Bits192)),
            "p384_hqc192" => Some(Hybrid(Bits192)),
            "x448_hqc192" => Some(Hybrid(Bits192)),

            "hqc256" => Some(QuantumSafe(Bits256)),
            "p521_hqc256" => Some(Hybrid(Bits256)),

            _ => None,
        };

        if let Some(ke) = ke_setting {
            Ok(ke)
        } else {
            Err(TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID_CASE.into())
        }
    }
}

/// Checks if the TLS 1.3 Key Exchange (KE) are satified the compliance
fn assert_tls13_ke_compliance(
    kes: std::slice::Iter<'_, impl AsRef<str>>,
    classical_choice: ClassicalAlgoChoice,
    hybrid_choice: HybridAlgoChoice,
    quantum_safe_choice: QuantumSafeAlgoChoice,
    desired_strength: NISTSecurityStrengthBits,
) -> crate::Result<()> {
    for k in kes {
        let bit_strength = match KESettings::try_from(k.as_ref())? {
            Hybrid(hybrid_bit_strength) => {
                if hybrid_choice == pb_api::HybridAlgoChoice::HYBRID_ALGORITHMS_FORBID {
                    Err(TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID_CASE)?
                }
                hybrid_bit_strength
            }
            Classical(classical_bit_strength) => {
                if classical_choice == pb_api::ClassicalAlgoChoice::CLASSICAL_ALGORITHMS_FORBID {
                    Err(TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID_CASE)?
                }
                classical_bit_strength
            }
            QuantumSafe(quantum_bit_strength) => {
                if quantum_safe_choice
                    == pb_api::QuantumSafeAlgoChoice::QUANTUM_SAFE_ALGORITHMS_FORBID
                {
                    Err(TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID_CASE)?
                }
                quantum_bit_strength
            }
        };

        if bit_strength < BitStrength::from(desired_strength) {
            return Err(TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID_CASE.into());
        }
    }
    Ok(())
}

/// Checks that the TLS 1.3 Key Exchange (KE) and Ciphersuite are satisfied by the configuration.
fn assert_tls13_compliance(tls13_config: &TLSv13Config) -> crate::Result<()> {
    let kes: &Vec<String> = &tls13_config.ke;
    let compliance = tls13_config.compliance.as_ref().unwrap_or_default();
    let hybrid_choice = compliance.hybrid_choice.enum_value_or_default();
    let classical_choice = compliance.classical_choice.enum_value_or_default();
    let quantum_safe_choice = compliance.quantum_safe_choice.enum_value_or_default();
    let desired_strength = compliance.bit_strength_choice.enum_value_or_default();

    assert_tls13_ke_compliance(
        kes.iter(),
        classical_choice,
        hybrid_choice,
        quantum_safe_choice,
        desired_strength,
    )?;

    Ok(())
}

/// Checks that the policy is satisfied by the configuration.
pub(crate) fn assert_compliance(cfg: &pb_api::Configuration) -> crate::Result<()> {
    let Some(tls13) = super::get_tls13_config(cfg) else {
        return Ok(());
    };
    assert_tls13_compliance(tls13)
}

#[cfg(test)]
mod test {
    use super::assert_compliance;
    use protobuf::text_format::parse_from_str;

    /// Tests the default compliance: it accepts post quantum and hybrid.
    #[test]
    fn test_default_tls13_compliance() {
        let cfg = parse_from_str::<pb_api::Configuration>(
            r#"
          client <
            tls <
              common_options <
                tls13 <
                  ke: "kyber512"
                  ke: "p256_kyber512"
                >
              >
            >
          >
          "#,
        )
        .unwrap();
        assert!(assert_compliance(&cfg).is_ok());
    }

    /// Tests the default compliance: it allows purely classical kes.
    #[test]
    fn test_default_tls13_compliance_classical() {
        let cfg = parse_from_str::<pb_api::Configuration>(
            r#"
          client <
            tls <
              common_options <
                tls13 <
                  ke: "prime256v1"
                  ke: "X25519"
                  ke: "X448"
                >
              >
            >
          >
          "#,
        )
        .unwrap();
        assert!(assert_compliance(&cfg).is_ok());
    }

    #[test]
    fn test_tls13_compliance_no_hybrid() {
        let cfg = parse_from_str::<pb_api::Configuration>(
            r#"
          client <
            tls <
              common_options <
                tls13 <
                  ke: "p256_kyber512"
                  compliance <
                    hybrid_choice: HYBRID_ALGORITHMS_FORBID
                  >
                >
              >
            >
          >
          "#,
        )
        .unwrap();
        assert!(assert_compliance(&cfg).is_err());
    }

    #[test]
    fn test_tls13_compliance_bit_strength() {
        let cfg = parse_from_str::<pb_api::Configuration>(
            r#"
          client <
            tls <
              common_options <
                  tls13 <
                      ke: "p256_kyber512"
                      compliance <
                          bit_strength_choice: BIT_STRENGTH_AT_LEAST_128
                      >
                  >
              >
            >
          >
          "#,
        )
        .unwrap();
        assert!(assert_compliance(&cfg).is_ok());
    }

    #[test]
    fn test_tls13_compliance_insufficient_bit_strength() {
        let cfg = parse_from_str::<pb_api::Configuration>(
            r#"
          client <
            tls <
              common_options <
                tls13 <
                  ke: "hqc192"
                  compliance <
                    bit_strength_choice: BIT_STRENGTH_AT_LEAST_256
                  >
                >
              >
            >
          >
          "#,
        )
        .unwrap();
        assert!(assert_compliance(&cfg).is_err());
    }

    #[test]
    fn test_tls13_compliance_classical_bit_strength() {
        let cfg = parse_from_str::<pb_api::Configuration>(
            r#"
          client <
            tls <
              common_options <
                tls13 <
                  ke: "brainpoolP256r1"
                  ke: "brainpoolP384r1"
                  ke: "brainpoolP512r1"
                  ke: "sect283k1"
                  ke: "sect283r1"
                  ke: "sect409k1"
                  ke: "sect409r1"
                  ke: "sect571k1"
                  ke: "sect571r1"
                  ke: "X25519"
                  ke: "prime256v1"
                  ke: "X448"
                  ke: "secp256k1"
                  ke: "secp384r1"
                  ke: "secp521r1"
                  compliance <
                    bit_strength_choice: BIT_STRENGTH_AT_LEAST_128
                    classical_choice: CLASSICAL_ALGORITHMS_ALLOW
                  >
                >
              >
            >
          >
          "#,
        )
        .unwrap();
        assert!(assert_compliance(&cfg).is_ok());
    }
}
