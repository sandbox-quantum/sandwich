// Copyright 2023 SandboxAQ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Defines [`BitStength`], [`AlgorithmQuantumness`] enums and [`assert_compliance`] methof.
//!
//! Author: lfousseaq

/// Extracts the list of allowed key exchange mechanisms (KEM) from the Configuration.
fn get_kems(cfg: &pb_api::Configuration) -> crate::Result<&std::vec::Vec<std::string::String>> {
    use pb_api::configuration::configuration as pb_configuration;
    cfg.opts
        .as_ref()
        .ok_or_else(|| pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE.into())
        .and_then(|oneof| match oneof {
            pb_configuration::Opts::Client(c) => Ok(&c.tls().common_options.kem),
            pb_configuration::Opts::Server(s) => Ok(&s.tls().common_options.kem),
            _ => Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE.into()),
        })
}

/// Represents the AES bit size equivalent hardness of breaking an algorithm.
#[derive(Copy, Clone, PartialEq, PartialOrd, Eq)]
enum BitStrength {
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

impl std::convert::TryFrom<&str> for AlgorithmQuantumness {
    type Error = crate::Error;

    /// Converts string to AlgorithmQuantumness and its corresponding BitStrength
    fn try_from(alg: &str) -> crate::Result<Self> {
        match alg {
            "brainpoolP384r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits192)),
            "brainpoolP512r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits256)),
            "prime256v1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits256)),
            "secp160k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits128)),
            "secp160r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits128)),
            "secp160r2" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits128)),
            "secp192k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits192)),
            "secp224k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits192)),
            "secp224r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits192)),
            "secp256k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits256)),
            "secp384r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits256)),
            "secp521r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits256)),
            "sect163k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits128)),
            "sect163r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits128)),
            "sect163r2" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits128)),
            "sect193r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits192)),
            "sect193r2" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits192)),
            "sect233k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits192)),
            "sect233r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits192)),
            "sect239k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits192)),
            "sect283k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits256)),
            "sect283r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits256)),
            "sect409k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits128)),
            "sect409r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits256)),
            "sect571k1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits256)),
            "sect571r1" => Ok(AlgorithmQuantumness::Classical(BitStrength::Bits256)),
            "bikel1" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "bikel3" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "frodo1344aes" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "frodo1344shake" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "frodo640aes" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "frodo640shake" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "frodo976aes" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "frodo976shake" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "hqc128" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "hqc192" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits192)),
            "hqc256" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits256)),
            "kyber1024" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "kyber512" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "kyber768" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "kyber90s1024" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "kyber90s512" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "kyber90s768" => Ok(AlgorithmQuantumness::QuantumSafe(BitStrength::Bits128)),
            "p256_bikel1" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits256)),
            "p256_frodo640aes" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p256_frodo640shake" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p256_hqc128" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p256_kyber512" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits256)),
            "p256_kyber90s512" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p384_bikel3" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p384_frodo976aes" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p384_frodo976shake" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p384_hqc192" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p384_kyber768" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p384_kyber90s768" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p521_frodo1344aes" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p521_frodo1344shake" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p521_hqc256" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p521_kyber1024" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            "p521_kyber90s1024" => Ok(AlgorithmQuantumness::Hybrid(BitStrength::Bits128)),
            _ => Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE.into()),
        }
    }
}

/// It checks that the bit strength of the key is at least as strong as the desired strength
fn assert_bit_strength(
    bit_strength: BitStrength,
    desired_strength: pb_api::NISTSecurityStrengthBits,
) -> crate::Result<()> {
    match desired_strength {
        pb_api::NISTSecurityStrengthBits::BIT_STRENGTH_AT_LEAST_128 => {
            if bit_strength < BitStrength::Bits128 {
                Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE)?
            }
        }
        pb_api::NISTSecurityStrengthBits::BIT_STRENGTH_AT_LEAST_192 => {
            if bit_strength < BitStrength::Bits192 {
                Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE)?
            }
        }
        pb_api::NISTSecurityStrengthBits::BIT_STRENGTH_AT_LEAST_256 => {
            if bit_strength < BitStrength::Bits256 {
                Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE)?
            }
        }
    }
    Ok(())
}

/// If the user has specified a compliance policy, then check that the policy is satisfied by the
/// configuration
pub(super) fn assert_compliance(cfg: &pb_api::Configuration) -> crate::Result<()> {
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
                    Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE)?
                }
                assert_bit_strength(hybrid_bit_strength, desired_strength)?;
            }
            AlgorithmQuantumness::Classical(classical_bit_strength) => {
                if classical_choice == pb_api::ClassicalAlgoChoice::CLASSICAL_ALGORITHMS_FORBID {
                    Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE)?
                }
                assert_bit_strength(classical_bit_strength, desired_strength)?;
            }
            AlgorithmQuantumness::QuantumSafe(quantum_bit_strength) => {
                if quantum_choice == pb_api::QuantumSafeAlgoChoice::QUANTUM_SAFE_ALGORITHMS_FORBID {
                    Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE)?
                }
                assert_bit_strength(quantum_bit_strength, desired_strength)?;
            }
        }
    }
    Ok(())
}
