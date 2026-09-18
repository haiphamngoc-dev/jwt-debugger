//! Cryptographic algorithm definitions and algorithm families supported by JSON Web Signatures (JWS).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

use super::error::JwtError;

/// Supported cryptographic algorithms defined in RFC 7518 (JSON Web Algorithms).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JwtAlgorithm {
    // HMAC
    /// HMAC using SHA-256 hash algorithm.
    HS256,
    /// HMAC using SHA-384 hash algorithm.
    HS384,
    /// HMAC using SHA-512 hash algorithm.
    HS512,

    // RSA PKCS#1 v1.5
    /// RSASSA-PKCS1-v1_5 using SHA-256 hash algorithm.
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384 hash algorithm.
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512 hash algorithm.
    RS512,

    // RSA-PSS
    /// RSASSA-PSS using SHA-256 hash algorithm and MGF1 with SHA-256.
    PS256,
    /// RSASSA-PSS using SHA-384 hash algorithm and MGF1 with SHA-384.
    PS384,
    /// RSASSA-PSS using SHA-512 hash algorithm and MGF1 with SHA-512.
    PS512,

    // ECDSA
    /// ECDSA using P-256 curve and SHA-256 hash algorithm.
    ES256,
    /// ECDSA using P-384 curve and SHA-384 hash algorithm.
    ES384,
    /// ECDSA using P-521 curve and SHA-512 hash algorithm.
    ES512,

    // EdDSA
    /// EdDSA signature algorithms (e.g. Ed25519).
    EdDSA,

    // Unsecured
    /// No digital signature or MAC performed (`"none"` algorithm).
    None,
}

/// Cryptographic algorithm family grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmFamily {
    /// Symmetric HMAC keyed hash algorithm family (`HS256`, `HS384`, `HS512`).
    Hmac,
    /// Asymmetric RSA PKCS#1 v1.5 algorithm family (`RS256`, `RS384`, `RS512`).
    RsaPkcs1,
    /// Asymmetric RSA-PSS algorithm family (`PS256`, `PS384`, `PS512`).
    RsaPss,
    /// Asymmetric Elliptic Curve Digital Signature Algorithm (`ES256`, `ES384`, `ES512`).
    Ecdsa,
    /// Asymmetric Edwards-curve Digital Signature Algorithm (`EdDSA`).
    Eddsa,
    /// Unsecured algorithm family (`none`).
    None,
}

impl JwtAlgorithm {
    /// Returns the algorithm family that this algorithm belongs to.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwt_debugger::domain::{AlgorithmFamily, JwtAlgorithm};
    ///
    /// assert_eq!(JwtAlgorithm::HS256.family(), AlgorithmFamily::Hmac);
    /// assert_eq!(JwtAlgorithm::RS256.family(), AlgorithmFamily::RsaPkcs1);
    /// assert_eq!(JwtAlgorithm::ES256.family(), AlgorithmFamily::Ecdsa);
    /// ```
    pub fn family(&self) -> AlgorithmFamily {
        match self {
            Self::HS256 | Self::HS384 | Self::HS512 => AlgorithmFamily::Hmac,
            Self::RS256 | Self::RS384 | Self::RS512 => AlgorithmFamily::RsaPkcs1,
            Self::PS256 | Self::PS384 | Self::PS512 => AlgorithmFamily::RsaPss,
            Self::ES256 | Self::ES384 | Self::ES512 => AlgorithmFamily::Ecdsa,
            Self::EdDSA => AlgorithmFamily::Eddsa,
            Self::None => AlgorithmFamily::None,
        }
    }

    /// Returns `true` if the algorithm uses symmetric shared-secret cryptography (HMAC).
    ///
    /// # Examples
    ///
    /// ```
    /// use jwt_debugger::domain::JwtAlgorithm;
    ///
    /// assert!(JwtAlgorithm::HS256.is_symmetric());
    /// assert!(!JwtAlgorithm::RS256.is_symmetric());
    /// ```
    pub fn is_symmetric(&self) -> bool {
        matches!(self.family(), AlgorithmFamily::Hmac)
    }

    /// Returns `true` if the algorithm uses asymmetric public/private key cryptography.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwt_debugger::domain::JwtAlgorithm;
    ///
    /// assert!(JwtAlgorithm::RS256.is_asymmetric());
    /// assert!(JwtAlgorithm::ES256.is_asymmetric());
    /// assert!(!JwtAlgorithm::HS256.is_asymmetric());
    /// ```
    pub fn is_asymmetric(&self) -> bool {
        matches!(
            self.family(),
            AlgorithmFamily::RsaPkcs1
                | AlgorithmFamily::RsaPss
                | AlgorithmFamily::Ecdsa
                | AlgorithmFamily::Eddsa
        )
    }

    /// Returns `true` if the algorithm is the unsecured `"none"` algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwt_debugger::domain::JwtAlgorithm;
    ///
    /// assert!(JwtAlgorithm::None.is_unsecured());
    /// assert!(!JwtAlgorithm::HS256.is_unsecured());
    /// ```
    pub fn is_unsecured(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Returns the standard RFC 7518 string representation of the algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwt_debugger::domain::JwtAlgorithm;
    ///
    /// assert_eq!(JwtAlgorithm::HS256.as_str(), "HS256");
    /// assert_eq!(JwtAlgorithm::None.as_str(), "none");
    /// ```
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HS256 => "HS256",
            Self::HS384 => "HS384",
            Self::HS512 => "HS512",
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
            Self::PS256 => "PS256",
            Self::PS384 => "PS384",
            Self::PS512 => "PS512",
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
            Self::EdDSA => "EdDSA",
            Self::None => "none",
        }
    }
}

impl fmt::Display for JwtAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for JwtAlgorithm {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "HS256" => Ok(Self::HS256),
            "HS384" => Ok(Self::HS384),
            "HS512" => Ok(Self::HS512),
            "RS256" => Ok(Self::RS256),
            "RS384" => Ok(Self::RS384),
            "RS512" => Ok(Self::RS512),
            "PS256" => Ok(Self::PS256),
            "PS384" => Ok(Self::PS384),
            "PS512" => Ok(Self::PS512),
            "ES256" => Ok(Self::ES256),
            "ES384" => Ok(Self::ES384),
            "ES512" => Ok(Self::ES512),
            "EdDSA" => Ok(Self::EdDSA),
            "none" | "NONE" | "None" => Ok(Self::None),
            other => Err(JwtError::UnsupportedAlgorithm(other.to_string())),
        }
    }
}

impl Serialize for JwtAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for JwtAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_parsing() {
        assert_eq!(
            JwtAlgorithm::from_str("HS256").unwrap(),
            JwtAlgorithm::HS256
        );
        assert_eq!(
            JwtAlgorithm::from_str("RS256").unwrap(),
            JwtAlgorithm::RS256
        );
        assert_eq!(
            JwtAlgorithm::from_str("PS384").unwrap(),
            JwtAlgorithm::PS384
        );
        assert_eq!(
            JwtAlgorithm::from_str("ES256").unwrap(),
            JwtAlgorithm::ES256
        );
        assert_eq!(
            JwtAlgorithm::from_str("ES512").unwrap(),
            JwtAlgorithm::ES512
        );
        assert_eq!(
            JwtAlgorithm::from_str("EdDSA").unwrap(),
            JwtAlgorithm::EdDSA
        );
        assert_eq!(JwtAlgorithm::from_str("none").unwrap(), JwtAlgorithm::None);
        assert!(JwtAlgorithm::from_str("UNSUPPORTED").is_err());
    }

    #[test]
    fn test_algorithm_properties() {
        assert!(JwtAlgorithm::HS256.is_symmetric());
        assert!(!JwtAlgorithm::HS256.is_asymmetric());

        assert!(JwtAlgorithm::RS256.is_asymmetric());
        assert!(!JwtAlgorithm::RS256.is_symmetric());

        assert!(JwtAlgorithm::ES512.is_asymmetric());
        assert_eq!(JwtAlgorithm::ES512.family(), AlgorithmFamily::Ecdsa);

        assert!(JwtAlgorithm::None.is_unsecured());
    }
}
