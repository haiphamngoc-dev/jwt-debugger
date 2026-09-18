//! Standard registered claims (RFC 7519) and custom payload claim models.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Audience claim (`aud`) which can be either a single string or an array of strings as per RFC 7519.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Audience {
    /// Single audience principal identifier.
    Single(String),
    /// Multiple audience principal identifiers.
    Multiple(Vec<String>),
}

impl Audience {
    /// Checks whether the audience contains the expected principal string.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwt_debugger::domain::Audience;
    ///
    /// let single = Audience::Single("my-api".to_string());
    /// assert!(single.contains("my-api"));
    /// assert!(!single.contains("other-api"));
    ///
    /// let multiple = Audience::Multiple(vec!["api1".to_string(), "api2".to_string()]);
    /// assert!(multiple.contains("api1"));
    /// assert!(multiple.contains("api2"));
    /// assert!(!multiple.contains("api3"));
    /// ```
    pub fn contains(&self, expected: &str) -> bool {
        match self {
            Self::Single(s) => s == expected,
            Self::Multiple(vec) => vec.iter().any(|s| s == expected),
        }
    }

    /// Converts the audience into a vector of strings.
    ///
    /// # Examples
    ///
    /// ```
    /// use jwt_debugger::domain::Audience;
    ///
    /// let single = Audience::Single("api".to_string());
    /// assert_eq!(single.as_vec(), vec!["api"]);
    /// ```
    pub fn as_vec(&self) -> Vec<String> {
        match self {
            Self::Single(s) => vec![s.clone()],
            Self::Multiple(vec) => vec.clone(),
        }
    }
}

impl fmt::Display for Audience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(s) => write!(f, "{s}"),
            Self::Multiple(vec) => write!(f, "{}", vec.join(", ")),
        }
    }
}

impl Serialize for Audience {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Single(s) => serializer.serialize_str(s),
            Self::Multiple(vec) => vec.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Audience {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let val = serde_json::Value::deserialize(deserializer)?;
        match val {
            serde_json::Value::String(s) => Ok(Self::Single(s)),
            serde_json::Value::Array(arr) => {
                let mut strings = Vec::new();
                for item in arr {
                    if let serde_json::Value::String(s) = item {
                        strings.push(s);
                    } else {
                        return Err(serde::de::Error::custom(
                            "Audience array elements must be strings",
                        ));
                    }
                }
                Ok(Self::Multiple(strings))
            }
            _ => Err(serde::de::Error::custom(
                "Audience must be a string or array of strings",
            )),
        }
    }
}

/// Parses a `NumericDate` value from a JSON value (integer or floating point seconds since Unix epoch).
///
/// Returns `None` if the value is not a valid number.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use jwt_debugger::domain::claims::parse_numeric_date;
///
/// assert_eq!(parse_numeric_date(&json!(1700000000)), Some(1700000000));
/// assert_eq!(parse_numeric_date(&json!(1700000000.75)), Some(1700000000));
/// assert_eq!(parse_numeric_date(&json!("invalid")), None);
/// ```
pub fn parse_numeric_date(value: &serde_json::Value) -> Option<i64> {
    if let Some(n) = value.as_i64() {
        Some(n)
    } else if let Some(n) = value.as_u64() {
        i64::try_from(n).ok()
    } else {
        value.as_f64().map(|f| f.floor() as i64)
    }
}

/// Standard registered JWT claims defined in RFC 7519 Section 4.1 alongside arbitrary custom claims.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StandardClaims {
    /// Issuer (`iss`) claim. Identifies the principal that issued the JWT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Subject (`sub`) claim. Identifies the principal that is the subject of the JWT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Audience (`aud`) claim. Identifies the recipients that the JWT is intended for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Audience>,

    /// Expiration Time (`exp`) claim. Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// Not Before (`nbf`) claim. Identifies the time before which the JWT MUST NOT be accepted for processing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// Issued At (`iat`) claim. Identifies the time at which the JWT was issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// JWT ID (`jti`) claim. Provides a unique identifier for the JWT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Additional custom claims present in the payload.
    #[serde(flatten)]
    pub custom: serde_json::Map<String, serde_json::Value>,
}

impl StandardClaims {
    /// Extracts registered and custom claims from a raw JSON payload object.
    ///
    /// # Arguments
    ///
    /// * `value` - JSON object representing the JWT payload.
    ///
    /// # Examples
    ///
    /// ```
    /// use serde_json::json;
    /// use jwt_debugger::domain::StandardClaims;
    ///
    /// let payload = json!({
    ///     "iss": "https://auth.example.com",
    ///     "sub": "user_123",
    ///     "exp": 1700000000,
    ///     "roles": ["admin", "editor"]
    /// });
    ///
    /// let claims = StandardClaims::from_json_value(&payload);
    /// assert_eq!(claims.iss.as_deref(), Some("https://auth.example.com"));
    /// assert_eq!(claims.sub.as_deref(), Some("user_123"));
    /// assert_eq!(claims.exp, Some(1700000000));
    /// assert!(claims.custom.contains_key("roles"));
    /// ```
    pub fn from_json_value(value: &serde_json::Value) -> Self {
        let obj = value.as_object();

        let iss = obj
            .and_then(|o| o.get("iss"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let sub = obj
            .and_then(|o| o.get("sub"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string);
        let jti = obj
            .and_then(|o| o.get("jti"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string);

        let aud = obj
            .and_then(|o| o.get("aud"))
            .and_then(|v| serde_json::from_value::<Audience>(v.clone()).ok());

        let exp = obj.and_then(|o| o.get("exp")).and_then(parse_numeric_date);
        let nbf = obj.and_then(|o| o.get("nbf")).and_then(parse_numeric_date);
        let iat = obj.and_then(|o| o.get("iat")).and_then(parse_numeric_date);

        let mut custom = serde_json::Map::new();
        if let Some(map) = obj {
            for (k, v) in map {
                if !matches!(
                    k.as_str(),
                    "iss" | "sub" | "aud" | "exp" | "nbf" | "iat" | "jti"
                ) {
                    custom.insert(k.clone(), v.clone());
                }
            }
        }

        Self {
            iss,
            sub,
            aud,
            exp,
            nbf,
            iat,
            jti,
            custom,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_audience_single_and_multiple() {
        let aud_single = serde_json::from_value::<Audience>(json!("api.example.com")).unwrap();
        assert_eq!(aud_single, Audience::Single("api.example.com".to_string()));
        assert!(aud_single.contains("api.example.com"));
        assert!(!aud_single.contains("other.example.com"));
        assert_eq!(aud_single.to_string(), "api.example.com");

        let aud_multi = serde_json::from_value::<Audience>(json!(["api1", "api2"])).unwrap();
        assert_eq!(
            aud_multi,
            Audience::Multiple(vec!["api1".to_string(), "api2".to_string()])
        );
        assert!(aud_multi.contains("api1"));
        assert!(aud_multi.contains("api2"));
        assert_eq!(aud_multi.to_string(), "api1, api2");
    }

    #[test]
    fn test_standard_claims_extraction() {
        let payload = json!({
            "iss": "auth.server",
            "sub": "user_42",
            "aud": ["app1", "app2"],
            "exp": 1700000000,
            "nbf": 1699990000,
            "iat": 1699990000,
            "jti": "jwt-uuid-1",
            "tenant_id": 999
        });

        let claims = StandardClaims::from_json_value(&payload);
        assert_eq!(claims.iss.as_deref(), Some("auth.server"));
        assert_eq!(claims.sub.as_deref(), Some("user_42"));
        assert!(claims.aud.as_ref().unwrap().contains("app1"));
        assert_eq!(claims.exp, Some(1700000000));
        assert_eq!(claims.jti.as_deref(), Some("jwt-uuid-1"));
        assert_eq!(claims.custom.get("tenant_id"), Some(&json!(999)));
    }
}
