//! Canonical workflow, method, and action signatures.

use std::fmt;
use std::sync::Arc;

use gantry_core::unicode::{is_nfc, is_xid_continue, is_xid_start};

use crate::generated::RecoveryClass;
use crate::{CanonicalCallableIdentity, CanonicalPath, TypeDescriptor};

/// Receiver ownership and caller-place access selected by static analysis.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReceiverMode {
    /// V1 `self`: an immutable local logical copy.
    LocalCopy,
    /// V1 `mut self`: a mutable local logical copy that never aliases its caller.
    MutableLocalCopy,
    /// A consuming receiver whose value is transferred into the call frame.
    Owned,
    /// A nonmutating temporary loan of the caller's place.
    SharedPlace,
    /// An exclusive temporary loan that may mutate the caller's place.
    ExclusivePlace,
}

impl ReceiverMode {
    /// Maps the two receiver forms admitted by the V1 parser.
    #[must_use]
    pub const fn from_v1_mutability(mutable: bool) -> Self {
        if mutable {
            Self::MutableLocalCopy
        } else {
            Self::LocalCopy
        }
    }

    /// Returns whether assignments through this receiver update its caller's place.
    #[must_use]
    pub const fn mutates_caller_place(self) -> bool {
        matches!(self, Self::ExclusivePlace)
    }

    /// Returns whether invocation creates an independent local receiver copy.
    #[must_use]
    pub const fn copies_receiver(self) -> bool {
        matches!(self, Self::LocalCopy | Self::MutableLocalCopy)
    }

    /// Returns whether invocation transfers receiver ownership into the call frame.
    #[must_use]
    pub const fn consumes_receiver(self) -> bool {
        matches!(self, Self::Owned)
    }

    /// Returns whether invocation acquires a shared temporary caller-place loan.
    #[must_use]
    pub const fn borrows_shared_place(self) -> bool {
        matches!(self, Self::SharedPlace)
    }

    /// Returns whether invocation acquires an exclusive temporary caller-place loan.
    #[must_use]
    pub const fn borrows_exclusive_place(self) -> bool {
        matches!(self, Self::ExclusivePlace)
    }

    /// Returns whether invocation requires an addressable caller place.
    #[must_use]
    pub const fn requires_caller_place(self) -> bool {
        matches!(self, Self::SharedPlace | Self::ExclusivePlace)
    }

    /// Returns the stable descriptive spelling used by IR inspection.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::LocalCopy => "local-copy",
            Self::MutableLocalCopy => "mutable-local-copy",
            Self::Owned => "owned",
            Self::SharedPlace => "shared-place",
            Self::ExclusivePlace => "exclusive-place",
        }
    }

    const fn signature_spelling(self) -> Option<&'static str> {
        match self {
            Self::LocalCopy => Some("self"),
            Self::MutableLocalCopy => Some("mut self"),
            Self::SharedPlace => Some("shared self"),
            Self::Owned | Self::ExclusivePlace => None,
        }
    }
}

/// Mutability and type of one workflow parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowParameter {
    /// Whether the source parameter is mutable.
    pub mutable: bool,
    /// Exact static parameter type.
    pub ty: TypeDescriptor,
}

/// Name and type of one action parameter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionParameter {
    name: Arc<str>,
    ty: TypeDescriptor,
}

impl ActionParameter {
    /// Constructs one exact NFC action parameter.
    pub fn new(name: &str, ty: TypeDescriptor) -> Result<Self, SignatureError> {
        validate_identifier(name)?;
        Ok(Self {
            name: Arc::from(name),
            ty,
        })
    }

    /// Returns the exact source parameter name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the canonical static type.
    #[must_use]
    pub const fn ty(&self) -> &TypeDescriptor {
        &self.ty
    }
}

/// One canonical signature string used as portable metadata.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalSignature(Arc<str>);

impl CanonicalSignature {
    /// Constructs one free-workflow signature.
    #[must_use]
    pub fn function(
        path: &CanonicalPath,
        parameters: &[WorkflowParameter],
        result: &TypeDescriptor,
    ) -> Self {
        let mut output = format!("fn {}(", path.as_str());
        push_workflow_parameters(&mut output, parameters);
        output.push_str(")->");
        output.push_str(&result.canonical_string());
        Self(Arc::from(output))
    }

    /// Constructs one closed generic callable signature.
    #[must_use]
    pub fn concrete_function(
        identity: &CanonicalCallableIdentity,
        parameters: &[WorkflowParameter],
        result: &TypeDescriptor,
    ) -> Self {
        let mut output = format!("fn {}(", identity.as_str());
        push_workflow_parameters(&mut output, parameters);
        output.push_str(")->");
        output.push_str(&result.canonical_string());
        Self(Arc::from(output))
    }

    /// Constructs one inherent-method signature.
    pub fn method(
        receiver_type: &CanonicalPath,
        method: &str,
        receiver_mode: ReceiverMode,
        parameters: &[WorkflowParameter],
        result: &TypeDescriptor,
    ) -> Result<Self, SignatureError> {
        validate_identifier(method)?;
        let mut output = format!("fn <{}>::{}(", receiver_type.as_str(), method);
        output.push_str(
            receiver_mode
                .signature_spelling()
                .ok_or(SignatureError::UnsupportedReceiverMode)?,
        );
        if !parameters.is_empty() {
            output.push(',');
            push_workflow_parameters(&mut output, parameters);
        }
        output.push_str(")->");
        output.push_str(&result.canonical_string());
        Ok(Self(Arc::from(output)))
    }

    /// Constructs one action signature with declaration-order named parameters.
    #[must_use]
    pub fn action(
        recovery: RecoveryClass,
        path: &CanonicalPath,
        parameters: &[ActionParameter],
        result: &TypeDescriptor,
    ) -> Self {
        let mut output = format!("action[{}] {}(", recovery.wire_name(), path.as_str());
        for (index, parameter) in parameters.iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push_str(parameter.name());
            output.push(':');
            output.push_str(&parameter.ty().canonical_string());
        }
        output.push_str(")->");
        output.push_str(&result.canonical_string());
        Self(Arc::from(output))
    }

    /// Returns the exact canonical metadata spelling.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Rejection of a noncanonical signature component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureError {
    /// A method or action parameter name is not one exact NFC XID identifier.
    InvalidIdentifier,
    /// The receiver mode has no source-compatible V1 signature spelling.
    UnsupportedReceiverMode,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentifier => "signature identifier is not canonical",
            Self::UnsupportedReceiverMode => "receiver mode is not admitted by V1 signatures",
        })
    }
}

impl std::error::Error for SignatureError {}

fn push_workflow_parameters(output: &mut String, parameters: &[WorkflowParameter]) {
    for (index, parameter) in parameters.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        if parameter.mutable {
            output.push_str("mut ");
        }
        output.push_str(&parameter.ty.canonical_string());
    }
}

fn validate_identifier(value: &str) -> Result<(), SignatureError> {
    let mut scalars = value.chars();
    if !is_nfc(value)
        || !scalars
            .next()
            .is_some_and(|scalar| scalar == '_' || is_xid_start(scalar))
        || !scalars.all(is_xid_continue)
    {
        return Err(SignatureError::InvalidIdentifier);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ActionParameter, CanonicalSignature, ReceiverMode, SignatureError, WorkflowParameter,
    };
    use crate::generated::RecoveryClass;
    use crate::{CanonicalCallableIdentity, CanonicalPath, TypeDescriptor};

    #[test]
    fn signatures_match_the_normative_examples() {
        let main = CanonicalPath::new("crate::main")
            .unwrap_or_else(|_| unreachable!("constant path is canonical"));
        let report = CanonicalPath::new("crate::domain::Report")
            .unwrap_or_else(|_| unreachable!("constant path is canonical"));
        let report_type = TypeDescriptor::declared(report.clone());
        assert_eq!(
            CanonicalSignature::function(
                &main,
                &[WorkflowParameter {
                    mutable: false,
                    ty: TypeDescriptor::STRING,
                }],
                &report_type,
            )
            .as_str(),
            "fn crate::main(String)->crate::domain::Report"
        );
        assert_eq!(
            CanonicalSignature::method(
                &report,
                "revise",
                ReceiverMode::MutableLocalCopy,
                &[WorkflowParameter {
                    mutable: false,
                    ty: TypeDescriptor::STRING,
                }],
                &report_type,
            )
            .map(|signature| signature.to_string()),
            Ok(
                "fn <crate::domain::Report>::revise(mut self,String)->crate::domain::Report"
                    .to_owned()
            )
        );
        assert_eq!(
            CanonicalSignature::method(
                &report,
                "inspect",
                ReceiverMode::SharedPlace,
                &[],
                &TypeDescriptor::INT,
            )
            .map(|signature| signature.to_string()),
            Ok("fn <crate::domain::Report>::inspect(shared self)->Int".to_owned())
        );
        assert_eq!(
            ReceiverMode::from_v1_mutability(false),
            ReceiverMode::LocalCopy
        );
        assert_eq!(
            ReceiverMode::from_v1_mutability(true),
            ReceiverMode::MutableLocalCopy
        );
        assert!(!ReceiverMode::LocalCopy.mutates_caller_place());
        assert!(!ReceiverMode::MutableLocalCopy.mutates_caller_place());
        assert!(ReceiverMode::ExclusivePlace.mutates_caller_place());
        assert_eq!(ReceiverMode::Owned.wire_name(), "owned");
        assert_eq!(ReceiverMode::SharedPlace.wire_name(), "shared-place");
        let preserve = CanonicalPath::new("crate::preserve")
            .unwrap_or_else(|_| unreachable!("constant path is canonical"));
        let concrete =
            CanonicalCallableIdentity::free(&preserve, std::slice::from_ref(&report_type));
        assert_eq!(
            CanonicalSignature::concrete_function(
                &concrete,
                &[WorkflowParameter {
                    mutable: false,
                    ty: report_type.clone(),
                }],
                &report_type,
            )
            .as_str(),
            "fn crate::preserve<crate::domain::Report>(crate::domain::Report)->crate::domain::Report"
        );
    }

    #[test]
    fn action_signatures_keep_parameter_names_and_recovery_class() {
        let path = CanonicalPath::new("crate::search")
            .unwrap_or_else(|_| unreachable!("constant path is canonical"));
        let request = CanonicalPath::new("crate::SearchRequest")
            .unwrap_or_else(|_| unreachable!("constant path is canonical"));
        let parameter = ActionParameter::new("request", TypeDescriptor::declared(request));
        assert!(parameter.is_ok());
        assert_eq!(
            CanonicalSignature::action(
                RecoveryClass::ReadOnly,
                &path,
                &[parameter.unwrap_or_else(|_| unreachable!("checked above"))],
                &TypeDescriptor::list(TypeDescriptor::STRING),
            )
            .as_str(),
            "action[read_only] crate::search(request:crate::SearchRequest)->List<String>"
        );
        assert_eq!(
            ActionParameter::new("A\u{301}", TypeDescriptor::STRING),
            Err(SignatureError::InvalidIdentifier)
        );
    }
}
