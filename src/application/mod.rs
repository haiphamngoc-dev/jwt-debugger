//! Application layer providing core use cases: JWT decoding, inspection, claim validation, and signature verification.

pub mod decode;
pub mod inspect;
pub mod validate_claims;
pub mod verify;

pub use decode::{
    DecodeMetadata, DecodedJwtReport, DecodedSignatureReport, decode_jwt, decode_signature_only,
};
pub use inspect::{
    InspectionReport, SignatureInspection, StructureInspection, TimingInspection, inspect_jwt,
};
pub use validate_claims::{ClaimValidationOptions, validate_claims};
pub use verify::verify_jwt;
