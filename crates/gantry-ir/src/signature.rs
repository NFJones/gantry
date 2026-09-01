//! Canonical workflow, method, and action signatures.

use std::fmt;
use std::sync::Arc;

use gantry_core::unicode::{is_nfc, is_xid_continue, is_xid_start};

use crate::generated::RecoveryClass;
use crate::{CanonicalCallableIdentity, CanonicalPath, TypeDescriptor};

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
        mutable_receiver: bool,
        parameters: &[WorkflowParameter],
        result: &TypeDescriptor,
    ) -> Result<Self, SignatureError> {
        validate_identifier(method)?;
        let mut output = format!("fn <{}>::{}(", receiver_type.as_str(), method);
        output.push_str(if mutable_receiver { "mut self" } else { "self" });
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
}

impl fmt::Display for SignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("signature identifier is not canonical")
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
    use super::{ActionParameter, CanonicalSignature, SignatureError, WorkflowParameter};
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
                true,
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
