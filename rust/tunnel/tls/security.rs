// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Defines [`BitStrength`], [`AlgorithmQuantumness`] enums and [`assert_compliance`] methof.

use pb::TLSConfigurationError;

use pb_api::configuration::configuration as pb_configuration;
use pb_api::NISTSecurityStrengthBits;

/// Extracts the list of allowed key exchange mechanisms (KEM) from the Configuration.
fn get_kems(cfg: &pb_api::Configuration) -> crate::Result<&Vec<String>> {
    cfg.opts
        .as_ref()
        .ok_or_else(|| TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID_CASE.into())
        .and_then(|oneof| match oneof {
            pb_configuration::Opts::Client(c) => Ok(&c.tls().common_options.kem),
            pb_configuration::Opts::Server(s) => Ok(&s.tls().common_options.kem),
            _ => Err(TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID_CASE.into()),
        })
}

/// Represents the AES bit size equivalent hardness of breaking an algorithm.
#[derive(Copy, Clone, PartialEq, PartialOrd, Eq)]
enum BitStrength {
    Bits80 = 80,
    Bits96 = 96,
    Bits112 = 112,
    Bits128 = 128, // AES-128
    Bits192 = 192, // AES-192
    Bits256 = 256, // AES-256
}

/// A cryptographic algorithm: is it safe to attack from quantum computer, unsafe, or a hybrid.
#[derive(Copy, Clone, PartialEq, Eq)]
enum AlgorithmQuantumness {
    Classical(BitStrength),
    QuantumSafe(BitStrength),
    Hybrid(BitStrength),
}

impl TryFrom<&str> for AlgorithmQuantumness {
    type Error = crate::Error;

    /// Converts string to AlgorithmQuantumness and its corresponding BitStrength
    fn try_from(alg: &str) -> crate::Result<Self> {
        match alg {
            "brainpoolP384r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits192)),
            "brainpoolP512r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits256)),

            "prime256v1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits128)),

            "secp160k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits80)),
            "secp160r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits80)),
            "secp160r2" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits80)),

            "secp192k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits96)),

            "secp224k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits112)),
            "secp224r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits112)),

            "secp256k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits128)),
            "secp384r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits192)),
            "secp521r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits256)),

            "sect163k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits80)),
            "sect163r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits80)),
            "sect163r2" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits80)),

            "sect193r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits96)),
            "sect193r2" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits96)),

            "sect233k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits112)),
            "sect233r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits112)),

            "sect239k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits112)),
            "sect283k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits128)),
            "sect283r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits128)),

            "sect409k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits192)),
            "sect409r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits192)),

            "sect571k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits256)),
            "sect571r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits256)),

            "bikel1" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "bikel3" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits192)),

            "frodo1344aes" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits256)),
            "frodo1344shake" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits256)),
            "frodo640aes" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "frodo640shake" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "frodo976aes" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits192)),
            "frodo976shake" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits192)),

            "hqc128" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "hqc192" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits192)),
            "hqc256" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits256)),

            "kyber1024" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits256)),
            "kyber512" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "kyber768" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits192)),

            "kyber90s1024" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits256)),
            "kyber90s512" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "kyber90s768" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits192)),

            "p256_bikel1" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p256_frodo640aes" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p256_frodo640shake" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p256_hqc128" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p256_kyber512" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p256_kyber90s512" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),

            "p384_bikel3" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits192)),
            "p384_frodo976aes" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits192)),
            "p384_frodo976shake" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits192)),
            "p384_hqc192" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits192)),
            "p384_kyber768" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits192)),
            "p384_kyber90s768" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits192)),

            "p521_frodo1344aes" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits256)),
            "p521_frodo1344shake" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits256)),
            "p521_hqc256" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits256)),
            "p521_kyber1024" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits256)),
            "p521_kyber90s1024" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits256)),

            _ => Err(TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID_CASE.into()),
        }
    }
}

/// Checks that the bit strength of the key is at least as strong as the desired strength.
fn assert_bit_strength(
    bit_strength: BitStrength,
    desired_strength: NISTSecurityStrengthBits,
) -> crate::Result<()> {
    match desired_strength {
        NISTSecurityStrengthBits::BIT_STRENGTH_AT_LEAST_128 => {
            if bit_strength < BitStrength::Bits128 {
                Err(TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID_CASE)?
            }
        }
        NISTSecurityStrengthBits::BIT_STRENGTH_AT_LEAST_192 => {
            if bit_strength < BitStrength::Bits192 {
                Err(TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID_CASE)?
            }
        }
        NISTSecurityStrengthBits::BIT_STRENGTH_AT_LEAST_256 => {
            if bit_strength < BitStrength::Bits256 {
                Err(TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID_CASE)?
            }
        }
    }
    Ok(())
}

/// Checks that the policy is satisfied by the configuration.
pub(crate) fn assert_compliance(cfg: &pb_api::Configuration) -> crate::Result<()> {
    let kems = get_kems(cfg)?;
    let compliance = cfg.compliance.as_ref().unwrap_or_default();
    let hybrid_choice = compliance.hybrid_choice.enum_value_or_default();
    let classical_choice = compliance.classical_choice.enum_value_or_default();
    let quantum_choice = compliance.quantum_safe_choice.enum_value_or_default();
    let desired_strength = compliance.bit_strength_choice.enum_value_or_default();
    for k in kems.iter() {
        match AlgorithmQuantumness::try_from(k.as_str())? {
            AlgorithmQuantumness::Hybrid(hybrid_bit_strength) => {
                if hybrid_choice == pb_api::HybridAlgoChoice::HYBRID_ALGORITHMS_FORBID {
                    Err(TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID_CASE)?
                }
                assert_bit_strength(hybrid_bit_strength, desired_strength)?;
            }
            AlgorithmQuantumness::Classical(classical_bit_strength) => {
                if classical_choice == pb_api::ClassicalAlgoChoice::CLASSICAL_ALGORITHMS_FORBID {
                    Err(TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID_CASE)?
                }
                assert_bit_strength(classical_bit_strength, desired_strength)?;
            }
            AlgorithmQuantumness::QuantumSafe(quantum_bit_strength) => {
                if quantum_choice == pb_api::QuantumSafeAlgoChoice::QUANTUM_SAFE_ALGORITHMS_FORBID {
                    Err(TLSConfigurationError::TLSCONFIGURATIONERROR_INVALID_CASE)?
                }
                assert_bit_strength(quantum_bit_strength, desired_strength)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::assert_compliance;
    use protobuf::text_format::parse_from_str;

    /// Tests the default compliance: it accepts post quantum and hybrid.
    #[test]
    fn test_default_compliance() {
        let cfg = parse_from_str::<pb_api::Configuration>(
            r#"
          client <
            tls <
              common_options <
                kem: "kyber512"
                kem: "p256_kyber512"
              >
            >
          >
          "#,
        )
        .unwrap();
        assert!(assert_compliance(&cfg).is_ok());
    }

    /// Tests the default compliance: it forbids purely classical kems.
    #[test]
    fn test_default_compliance_no_classical() {
        let cfg = parse_from_str::<pb_api::Configuration>(
            r#"
          client <
            tls <
              common_options <
                kem: "prime256v1"
                kem: "kyber512"
                kem: "p256_kyber512"
              >
            >
          >
          "#,
        )
        .unwrap();
        assert!(assert_compliance(&cfg).is_err());
    }

    #[test]
    fn test_compliance_no_hybrid() {
        let cfg = parse_from_str::<pb_api::Configuration>(
            r#"
          client <
            tls <
              common_options <
                kem: "p256_kyber512"
              >
            >
          >
          compliance <
            hybrid_choice: HYBRID_ALGORITHMS_FORBID
          >
          "#,
        )
        .unwrap();
        assert!(assert_compliance(&cfg).is_err());
    }

    #[test]
    fn test_compliance_bit_strength() {
        let cfg = parse_from_str::<pb_api::Configuration>(
            r#"
          client <
            tls <
              common_options <
                kem: "p256_kyber512"
              >
            >
          >
          compliance <
            bit_strength_choice: BIT_STRENGTH_AT_LEAST_128
          >
          "#,
        )
        .unwrap();
        assert!(assert_compliance(&cfg).is_ok());
    }

    #[test]
    fn test_compliance_insufficient_bit_strength() {
        let cfg = parse_from_str::<pb_api::Configuration>(
            r#"
          client <
            tls <
              common_options <
                kem: "hqc192"
              >
            >
          >
          compliance <
            bit_strength_choice: BIT_STRENGTH_AT_LEAST_256
          >
          "#,
        )
        .unwrap();
        assert!(assert_compliance(&cfg).is_err());
    }
}
