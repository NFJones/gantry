//! Canonical concrete and template callable identities.

use std::fmt;
use std::sync::Arc;

use crate::{CanonicalPath, TypeDescriptor, TypeExpression};

/// One closed direct-call identity admitted by executable and durable artifacts.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalCallableIdentity(Arc<str>);

impl CanonicalCallableIdentity {
    /// Constructs a free-workflow identity with complete ordered type arguments.
    #[must_use]
    pub fn free(path: &CanonicalPath, arguments: &[TypeDescriptor]) -> Self {
        Self(Arc::from(format_free(
            path,
            arguments.iter().map(TypeDescriptor::canonical_string),
        )))
    }

    /// Constructs an inherent-method identity.
    pub fn inherent(
        receiver: &TypeDescriptor,
        method: &str,
        method_arguments: &[TypeDescriptor],
    ) -> Result<Self, CallableIdentityError> {
        validate_identifier(method)?;
        Ok(Self(Arc::from(format_method(
            &receiver.canonical_string(),
            None,
            method,
            method_arguments
                .iter()
                .map(TypeDescriptor::canonical_string),
        ))))
    }

    /// Constructs a selected trait-method identity.
    pub fn trait_method(
        receiver: &TypeDescriptor,
        trait_path: &CanonicalPath,
        trait_arguments: &[TypeDescriptor],
        method: &str,
        method_arguments: &[TypeDescriptor],
    ) -> Result<Self, CallableIdentityError> {
        validate_identifier(method)?;
        let trait_reference = format_free(
            trait_path,
            trait_arguments.iter().map(TypeDescriptor::canonical_string),
        );
        Ok(Self(Arc::from(format_method(
            &receiver.canonical_string(),
            Some(&trait_reference),
            method,
            method_arguments
                .iter()
                .map(TypeDescriptor::canonical_string),
        ))))
    }

    /// Strictly decodes one exact closed callable identity.
    pub fn from_canonical_string(
        value: &str,
        maximum_constructed_type_depth: u64,
    ) -> Result<Self, CallableIdentityError> {
        let parsed = ParsedIdentity::parse(value)?;
        let canonical = match parsed {
            ParsedIdentity::Free { path, arguments } => Self::free(
                &path,
                &decode_descriptors(&arguments, maximum_constructed_type_depth)?,
            ),
            ParsedIdentity::Inherent {
                receiver,
                method,
                method_arguments,
            } => Self::inherent(
                &TypeDescriptor::from_canonical_string_with_depth_limit(
                    receiver,
                    maximum_constructed_type_depth,
                )
                .map_err(|_| CallableIdentityError::InvalidCanonicalString)?,
                method,
                &decode_descriptors(&method_arguments, maximum_constructed_type_depth)?,
            )?,
            ParsedIdentity::TraitMethod {
                receiver,
                trait_path,
                trait_arguments,
                method,
                method_arguments,
            } => Self::trait_method(
                &TypeDescriptor::from_canonical_string_with_depth_limit(
                    receiver,
                    maximum_constructed_type_depth,
                )
                .map_err(|_| CallableIdentityError::InvalidCanonicalString)?,
                &trait_path,
                &decode_descriptors(&trait_arguments, maximum_constructed_type_depth)?,
                method,
                &decode_descriptors(&method_arguments, maximum_constructed_type_depth)?,
            )?,
        };
        if canonical.as_str() != value {
            return Err(CallableIdentityError::InvalidCanonicalString);
        }
        Ok(canonical)
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the closed receiver descriptor for an inherent or trait method.
    #[must_use]
    pub fn receiver_type(&self) -> Option<TypeDescriptor> {
        let receiver = match ParsedIdentity::parse(self.as_str()).ok()? {
            ParsedIdentity::Free { .. } => return None,
            ParsedIdentity::Inherent { receiver, .. }
            | ParsedIdentity::TraitMethod { receiver, .. } => receiver,
        };
        TypeDescriptor::from_canonical_string(receiver).ok()
    }
}

impl fmt::Display for CanonicalCallableIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One open-or-closed callable identity retained only by analysis artifacts.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalTemplateIdentity(Arc<str>);

impl CanonicalTemplateIdentity {
    /// Constructs a free-workflow template identity.
    #[must_use]
    pub fn free(path: &CanonicalPath, arguments: &[TypeExpression]) -> Self {
        Self(Arc::from(format_free(
            path,
            arguments
                .iter()
                .map(|argument| argument.as_str().to_owned()),
        )))
    }

    /// Constructs an inherent-method template identity.
    pub fn inherent(
        receiver: &TypeExpression,
        method: &str,
        method_arguments: &[TypeExpression],
    ) -> Result<Self, CallableIdentityError> {
        validate_identifier(method)?;
        Ok(Self(Arc::from(format_method(
            receiver.as_str(),
            None,
            method,
            method_arguments
                .iter()
                .map(|argument| argument.as_str().to_owned()),
        ))))
    }

    /// Constructs a trait-method template identity.
    pub fn trait_method(
        receiver: &TypeExpression,
        trait_path: &CanonicalPath,
        trait_arguments: &[TypeExpression],
        method: &str,
        method_arguments: &[TypeExpression],
    ) -> Result<Self, CallableIdentityError> {
        validate_identifier(method)?;
        let trait_reference = format_free(
            trait_path,
            trait_arguments
                .iter()
                .map(|argument| argument.as_str().to_owned()),
        );
        Ok(Self(Arc::from(format_method(
            receiver.as_str(),
            Some(&trait_reference),
            method,
            method_arguments
                .iter()
                .map(|argument| argument.as_str().to_owned()),
        ))))
    }

    /// Strictly decodes one canonical template identity.
    pub fn from_canonical_string(
        value: &str,
        maximum_constructed_type_depth: u64,
    ) -> Result<Self, CallableIdentityError> {
        let parsed = ParsedIdentity::parse(value)?;
        let canonical = match parsed {
            ParsedIdentity::Free { path, arguments } => Self::free(
                &path,
                &decode_expressions(&arguments, maximum_constructed_type_depth)?,
            ),
            ParsedIdentity::Inherent {
                receiver,
                method,
                method_arguments,
            } => Self::inherent(
                &TypeExpression::from_canonical_string(receiver, maximum_constructed_type_depth)
                    .map_err(|_| CallableIdentityError::InvalidCanonicalString)?,
                method,
                &decode_expressions(&method_arguments, maximum_constructed_type_depth)?,
            )?,
            ParsedIdentity::TraitMethod {
                receiver,
                trait_path,
                trait_arguments,
                method,
                method_arguments,
            } => Self::trait_method(
                &TypeExpression::from_canonical_string(receiver, maximum_constructed_type_depth)
                    .map_err(|_| CallableIdentityError::InvalidCanonicalString)?,
                &trait_path,
                &decode_expressions(&trait_arguments, maximum_constructed_type_depth)?,
                method,
                &decode_expressions(&method_arguments, maximum_constructed_type_depth)?,
            )?,
        };
        if canonical.as_str() != value {
            return Err(CallableIdentityError::InvalidCanonicalString);
        }
        Ok(canonical)
    }

    /// Returns the exact portable identity spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalTemplateIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Rejection of a malformed callable identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallableIdentityError {
    /// Input is not one exact canonical callable identity.
    InvalidCanonicalString,
}

impl fmt::Display for CallableIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("callable identity is not canonical")
    }
}

impl std::error::Error for CallableIdentityError {}

enum ParsedIdentity<'a> {
    Free {
        path: CanonicalPath,
        arguments: Vec<&'a str>,
    },
    Inherent {
        receiver: &'a str,
        method: &'a str,
        method_arguments: Vec<&'a str>,
    },
    TraitMethod {
        receiver: &'a str,
        trait_path: CanonicalPath,
        trait_arguments: Vec<&'a str>,
        method: &'a str,
        method_arguments: Vec<&'a str>,
    },
}

impl<'a> ParsedIdentity<'a> {
    fn parse(value: &'a str) -> Result<Self, CallableIdentityError> {
        if value.is_empty() || value.starts_with(char::is_whitespace) {
            return Err(CallableIdentityError::InvalidCanonicalString);
        }
        if !value.starts_with('<') {
            let (path, arguments) = split_application(value)?;
            return Ok(Self::Free {
                path: CanonicalPath::new(path)
                    .map_err(|_| CallableIdentityError::InvalidCanonicalString)?,
                arguments,
            });
        }

        let closing = matching_angle(value, 0)?;
        let inside = value
            .get(1..closing)
            .ok_or(CallableIdentityError::InvalidCanonicalString)?;
        let suffix = value
            .get(closing + 1..)
            .and_then(|suffix| suffix.strip_prefix("::"))
            .ok_or(CallableIdentityError::InvalidCanonicalString)?;
        let (method, method_arguments) = split_application(suffix)?;
        validate_identifier(method)?;
        if let Some(separator) = find_top_level(inside, " as ")? {
            let receiver = inside
                .get(..separator)
                .ok_or(CallableIdentityError::InvalidCanonicalString)?;
            let trait_reference = inside
                .get(separator + " as ".len()..)
                .ok_or(CallableIdentityError::InvalidCanonicalString)?;
            let (trait_path, trait_arguments) = split_application(trait_reference)?;
            Ok(Self::TraitMethod {
                receiver,
                trait_path: CanonicalPath::new(trait_path)
                    .map_err(|_| CallableIdentityError::InvalidCanonicalString)?,
                trait_arguments,
                method,
                method_arguments,
            })
        } else {
            Ok(Self::Inherent {
                receiver: inside,
                method,
                method_arguments,
            })
        }
    }
}

fn format_free(path: &CanonicalPath, arguments: impl Iterator<Item = String>) -> String {
    let arguments = arguments.collect::<Vec<_>>();
    if arguments.is_empty() {
        return path.as_str().to_owned();
    }
    format!("{}<{}>", path.as_str(), arguments.join(","))
}

fn format_method(
    receiver: &str,
    trait_reference: Option<&str>,
    method: &str,
    method_arguments: impl Iterator<Item = String>,
) -> String {
    let mut output = format!("<{receiver}");
    if let Some(trait_reference) = trait_reference {
        output.push_str(" as ");
        output.push_str(trait_reference);
    }
    output.push_str(">::");
    output.push_str(method);
    let arguments = method_arguments.collect::<Vec<_>>();
    if !arguments.is_empty() {
        output.push('<');
        output.push_str(&arguments.join(","));
        output.push('>');
    }
    output
}

fn split_application(value: &str) -> Result<(&str, Vec<&str>), CallableIdentityError> {
    let Some(opening) = value.find('<') else {
        if value.contains('>') || value.is_empty() {
            return Err(CallableIdentityError::InvalidCanonicalString);
        }
        return Ok((value, Vec::new()));
    };
    let closing = matching_angle(value, opening)?;
    if closing + 1 != value.len() {
        return Err(CallableIdentityError::InvalidCanonicalString);
    }
    let head = value
        .get(..opening)
        .filter(|head| !head.is_empty())
        .ok_or(CallableIdentityError::InvalidCanonicalString)?;
    let body = value
        .get(opening + 1..closing)
        .ok_or(CallableIdentityError::InvalidCanonicalString)?;
    Ok((head, split_top_level_arguments(body)?))
}

fn split_top_level_arguments(value: &str) -> Result<Vec<&str>, CallableIdentityError> {
    if value.is_empty() {
        return Err(CallableIdentityError::InvalidCanonicalString);
    }
    let mut arguments = Vec::new();
    let mut depth = 0_u64;
    let mut start = 0_usize;
    for (index, byte) in value.bytes().enumerate() {
        match byte {
            b'<' => {
                depth = depth
                    .checked_add(1)
                    .ok_or(CallableIdentityError::InvalidCanonicalString)?
            }
            b'>' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or(CallableIdentityError::InvalidCanonicalString)?;
            }
            b',' if depth == 0 => {
                arguments.push(
                    value
                        .get(start..index)
                        .filter(|argument| !argument.is_empty())
                        .ok_or(CallableIdentityError::InvalidCanonicalString)?,
                );
                start = index + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(CallableIdentityError::InvalidCanonicalString);
    }
    arguments.push(
        value
            .get(start..)
            .filter(|argument| !argument.is_empty())
            .ok_or(CallableIdentityError::InvalidCanonicalString)?,
    );
    Ok(arguments)
}

fn matching_angle(value: &str, opening: usize) -> Result<usize, CallableIdentityError> {
    if value.as_bytes().get(opening) != Some(&b'<') {
        return Err(CallableIdentityError::InvalidCanonicalString);
    }
    let mut depth = 0_u64;
    for (offset, byte) in value.as_bytes()[opening..].iter().copied().enumerate() {
        match byte {
            b'<' => {
                depth = depth
                    .checked_add(1)
                    .ok_or(CallableIdentityError::InvalidCanonicalString)?
            }
            b'>' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or(CallableIdentityError::InvalidCanonicalString)?;
                if depth == 0 {
                    return Ok(opening + offset);
                }
            }
            _ => {}
        }
    }
    Err(CallableIdentityError::InvalidCanonicalString)
}

fn find_top_level(value: &str, needle: &str) -> Result<Option<usize>, CallableIdentityError> {
    let mut depth = 0_u64;
    let bytes = value.as_bytes();
    let needle = needle.as_bytes();
    let mut index = 0_usize;
    while index < bytes.len() {
        match bytes[index] {
            b'<' => {
                depth = depth
                    .checked_add(1)
                    .ok_or(CallableIdentityError::InvalidCanonicalString)?
            }
            b'>' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or(CallableIdentityError::InvalidCanonicalString)?;
            }
            _ if depth == 0 && bytes[index..].starts_with(needle) => return Ok(Some(index)),
            _ => {}
        }
        index += 1;
    }
    if depth == 0 {
        Ok(None)
    } else {
        Err(CallableIdentityError::InvalidCanonicalString)
    }
}

fn decode_descriptors(
    values: &[&str],
    maximum_constructed_type_depth: u64,
) -> Result<Vec<TypeDescriptor>, CallableIdentityError> {
    values
        .iter()
        .map(|value| {
            TypeDescriptor::from_canonical_string_with_depth_limit(
                value,
                maximum_constructed_type_depth,
            )
            .map_err(|_| CallableIdentityError::InvalidCanonicalString)
        })
        .collect()
}

fn decode_expressions(
    values: &[&str],
    maximum_constructed_type_depth: u64,
) -> Result<Vec<TypeExpression>, CallableIdentityError> {
    values
        .iter()
        .map(|value| {
            TypeExpression::from_canonical_string(value, maximum_constructed_type_depth)
                .map_err(|_| CallableIdentityError::InvalidCanonicalString)
        })
        .collect()
}

fn validate_identifier(value: &str) -> Result<(), CallableIdentityError> {
    CanonicalPath::new(&format!("crate::{value}"))
        .map(|_| ())
        .map_err(|_| CallableIdentityError::InvalidCanonicalString)
}

#[cfg(test)]
mod tests {
    use super::{CanonicalCallableIdentity, CanonicalTemplateIdentity};
    use crate::{CanonicalPath, TypeDescriptor, TypeExpression};

    #[test]
    fn concrete_identities_match_the_normative_forms() {
        let preserve = CanonicalPath::new("crate::preserve")
            .unwrap_or_else(|_| unreachable!("constant path is canonical"));
        let report = TypeDescriptor::declared(
            CanonicalPath::new("crate::Report")
                .unwrap_or_else(|_| unreachable!("constant path is canonical")),
        );
        assert_eq!(
            CanonicalCallableIdentity::free(&preserve, std::slice::from_ref(&report)).as_str(),
            "crate::preserve<crate::Report>"
        );
        assert_eq!(
            CanonicalCallableIdentity::trait_method(
                &report,
                &CanonicalPath::new("crate::Convert")
                    .unwrap_or_else(|_| unreachable!("constant path is canonical")),
                &[TypeDescriptor::STRING],
                "convert",
                &[TypeDescriptor::declared(
                    CanonicalPath::new("crate::Compact")
                        .unwrap_or_else(|_| unreachable!("constant path is canonical")),
                )],
            )
            .map(|identity| identity.to_string()),
            Ok("<crate::Report as crate::Convert<String>>::convert<crate::Compact>".to_owned())
        );
    }

    #[test]
    fn template_identities_are_alpha_rename_independent() {
        let parameter = TypeExpression::parameter(0, 0, 8)
            .unwrap_or_else(|_| unreachable!("bounded parameter is valid"));
        let identity = CanonicalTemplateIdentity::free(
            &CanonicalPath::new("crate::preserve")
                .unwrap_or_else(|_| unreachable!("constant path is canonical")),
            &[parameter],
        );
        assert_eq!(identity.as_str(), "crate::preserve<^0.0>");
        assert_eq!(
            CanonicalTemplateIdentity::from_canonical_string(identity.as_str(), 8),
            Ok(identity)
        );
    }

    #[test]
    fn strict_identity_decoding_rejects_open_runtime_and_noncanonical_forms() {
        for value in [
            "crate::preserve<^0.0>",
            "crate::preserve< String>",
            "<crate::Report as crate::Convert<String>>::bad-name",
            "<crate::Report as crate::Convert<String>>::convert<>",
        ] {
            assert!(CanonicalCallableIdentity::from_canonical_string(value, 8).is_err());
        }
        let canonical = "<crate::Envelope<String>>::convert<crate::Compact>";
        assert_eq!(
            CanonicalCallableIdentity::from_canonical_string(canonical, 8)
                .map(|identity| identity.to_string()),
            Ok(canonical.to_owned())
        );
    }
}
