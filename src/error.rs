//! S3 error model: every failure maps to an S3 error code + HTTP status,
//! serialized as the standard S3 `Error` XML document.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Error {
    pub code: &'static str,
    pub status: u16,
    pub message: String,
}

impl fmt::Display for S3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}) {}", self.code, self.status, self.message)
    }
}

impl std::error::Error for S3Error {}

impl S3Error {
    pub fn new(code: &'static str, status: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            status,
            message: message.into(),
        }
    }

    pub fn no_such_bucket(bucket: &str) -> Self {
        Self::new(
            "NoSuchBucket",
            404,
            format!("The specified bucket does not exist: {bucket}"),
        )
    }
    pub fn no_such_key(key: &str) -> Self {
        Self::new(
            "NoSuchKey",
            404,
            format!("The specified key does not exist: {key}"),
        )
    }
    pub fn bucket_already_exists(bucket: &str) -> Self {
        Self::new(
            "BucketAlreadyExists",
            409,
            format!("The requested bucket name is not available: {bucket}"),
        )
    }
    pub fn invalid_bucket_name(name: &str) -> Self {
        Self::new(
            "InvalidBucketName",
            400,
            format!("The specified bucket is not valid: {name}"),
        )
    }
    pub fn invalid_argument(msg: impl Into<String>) -> Self {
        Self::new("InvalidArgument", 400, msg)
    }
    pub fn no_such_upload() -> Self {
        Self::new(
            "NoSuchUpload",
            404,
            "The specified upload does not exist. It may have been aborted or completed.",
        )
    }
    pub fn invalid_part() -> Self {
        Self::new(
            "InvalidPart",
            400,
            "One or more of the specified parts could not be found. The part may not have been uploaded, or the specified entity tag may not match the part's entity tag.",
        )
    }
    pub fn invalid_part_order() -> Self {
        Self::new(
            "InvalidPartOrder",
            400,
            "The list of parts was not in ascending order. Parts must be ordered by part number.",
        )
    }
    pub fn entity_too_small() -> Self {
        Self::new(
            "EntityTooSmall",
            400,
            "Your proposed upload is smaller than the minimum allowed object size. Each part must be at least 5 MB, except the last part.",
        )
    }
    pub fn entity_too_large() -> Self {
        Self::new(
            "EntityTooLarge",
            400,
            "Your proposed upload exceeds the maximum allowed object size.",
        )
    }
    pub fn access_denied() -> Self {
        Self::new("AccessDenied", 403, "Access Denied")
    }
    pub fn signature_does_not_match() -> Self {
        Self::new(
            "SignatureDoesNotMatch",
            403,
            "The request signature we calculated does not match the signature you provided. Check your key and signing method.",
        )
    }
    pub fn invalid_access_key_id() -> Self {
        Self::new(
            "InvalidAccessKeyId",
            403,
            "The AWS Access Key Id you provided does not exist in our records.",
        )
    }
    pub fn precondition_failed() -> Self {
        Self::new(
            "PreconditionFailed",
            412,
            "At least one of the preconditions you specified did not hold.",
        )
    }
    pub fn not_implemented() -> Self {
        Self::new(
            "NotImplemented",
            501,
            "A header or query you provided implies functionality that is not implemented.",
        )
    }
    pub fn method_not_allowed() -> Self {
        Self::new(
            "MethodNotAllowed",
            405,
            "The specified method is not allowed against this resource.",
        )
    }
    pub fn bucket_not_empty() -> Self {
        Self::new(
            "BucketNotEmpty",
            409,
            "The bucket you tried to delete is not empty.",
        )
    }
    pub fn invalid_range() -> Self {
        Self::new(
            "InvalidRange",
            416,
            "The requested range is not satisfiable.",
        )
    }
    pub fn bad_digest() -> Self {
        Self::new(
            "BadDigest",
            400,
            "The Content-MD5 you specified did not match what we received.",
        )
    }
    pub fn sha_mismatch() -> Self {
        Self::new(
            "XAmzContentSHA256Mismatch",
            400,
            "The provided 'x-amz-content-sha256' header does not match what was computed.",
        )
    }
    pub fn malformed_xml() -> Self {
        Self::new(
            "MalformedXML",
            400,
            "The XML you provided was not well-formed or did not validate against our published schema.",
        )
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new("InternalError", 500, msg)
    }
    pub fn invalid_object_state() -> Self {
        Self::new(
            "InvalidObjectState",
            400,
            "The operation is not valid for the object's state.",
        )
    }
}

/// Serialization of the S3 error document lives in `xml`.
pub fn error_xml(code: &str, message: &str, resource: &str, request_id: &str) -> String {
    crate::xml::Xml::new()
        .open("Error", &[("xmlns", XMLNS_S3)])
        .el("Code", code)
        .el("Message", message)
        .el("Resource", resource)
        .el("RequestId", request_id)
        .close("Error")
        .finish()
}

pub const XMLNS_S3: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_and_statuses() {
        let cases = [
            (S3Error::no_such_bucket("b"), "NoSuchBucket", 404),
            (S3Error::no_such_key("k"), "NoSuchKey", 404),
            (
                S3Error::bucket_already_exists("b"),
                "BucketAlreadyExists",
                409,
            ),
            (S3Error::invalid_bucket_name("b"), "InvalidBucketName", 400),
            (S3Error::invalid_argument("x"), "InvalidArgument", 400),
            (S3Error::no_such_upload(), "NoSuchUpload", 404),
            (S3Error::invalid_part(), "InvalidPart", 400),
            (S3Error::invalid_part_order(), "InvalidPartOrder", 400),
            (S3Error::entity_too_small(), "EntityTooSmall", 400),
            (S3Error::entity_too_large(), "EntityTooLarge", 400),
            (S3Error::access_denied(), "AccessDenied", 403),
            (
                S3Error::signature_does_not_match(),
                "SignatureDoesNotMatch",
                403,
            ),
            (S3Error::invalid_access_key_id(), "InvalidAccessKeyId", 403),
            (S3Error::precondition_failed(), "PreconditionFailed", 412),
            (S3Error::not_implemented(), "NotImplemented", 501),
            (S3Error::method_not_allowed(), "MethodNotAllowed", 405),
            (S3Error::bucket_not_empty(), "BucketNotEmpty", 409),
            (S3Error::invalid_range(), "InvalidRange", 416),
        ];
        for (err, code, status) in cases {
            assert_eq!(err.code, code);
            assert_eq!(err.status, status);
        }
    }

    #[test]
    fn error_xml_document() {
        let doc = error_xml("NoSuchKey", "gone", "/b/k", "req-1");
        assert!(doc.contains("<Error xmlns="));
        assert!(doc.contains("<Code>NoSuchKey</Code>"));
        assert!(doc.contains("<RequestId>req-1</RequestId>"));
        assert!(doc.contains("<Resource>/b/k</Resource>"));
    }
}
