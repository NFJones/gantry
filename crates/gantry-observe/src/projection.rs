//! Capability-filtered projection of protected event payloads.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use gantry_core::event::{EventEnvelope, ProtectedReference};
use gantry_core::portable::{DeliveryProjection, ProtectedReferenceClass};
use gantry_host::event::{
    ProjectedPayload, ProtectedPayload, ProtectedPayloadBundle, SinkDeliveryPolicy,
};

/// Projects exact protected bytes against one frozen sink policy.
pub fn project_payloads(
    event: &EventEnvelope,
    payloads: &[ProtectedPayload],
    policy: &SinkDeliveryPolicy,
) -> Result<ProtectedPayloadBundle, ProjectionError> {
    let mut supplied = BTreeMap::new();
    for payload in payloads {
        if supplied.insert(payload.reference.key(), payload).is_some() {
            return Err(ProjectionError::DuplicatePayload);
        }
    }

    let event_keys = event
        .protected_references()
        .iter()
        .map(ProtectedReference::key)
        .collect::<BTreeSet<_>>();
    if supplied.keys().any(|key| !event_keys.contains(key)) {
        return Err(ProjectionError::UnreferencedPayload);
    }

    let mut projected = Vec::with_capacity(event.protected_references().len());
    for reference in event.protected_references() {
        let payload = supplied
            .get(reference.key())
            .ok_or(ProjectionError::MissingPayload)?;
        if payload.reference.class() != reference.class() {
            return Err(ProjectionError::ClassMismatch);
        }
        let available = permitted(reference.class(), policy);
        projected.push(ProjectedPayload {
            reference: reference.clone(),
            projection: if available {
                DeliveryProjection::Available
            } else {
                DeliveryProjection::Redacted
            },
            bytes: available.then(|| Arc::clone(&payload.bytes)),
        });
    }
    Ok(ProtectedPayloadBundle::new(projected))
}

fn permitted(class: ProtectedReferenceClass, policy: &SinkDeliveryPolicy) -> bool {
    match class {
        ProtectedReferenceClass::RawOutput => policy.raw_output,
        ProtectedReferenceClass::OperationRequest => policy.capabilities.operation_request_content,
        ProtectedReferenceClass::NormalizedDecision
        | ProtectedReferenceClass::NormalizedOperationError
        | ProtectedReferenceClass::NormalizedValue => policy.capabilities.operation_result_content,
        ProtectedReferenceClass::IntegrationDiagnostic => {
            policy.capabilities.integration_diagnostics
        }
        ProtectedReferenceClass::SourceSnippet => policy.capabilities.source_snippets,
    }
}

/// Invalid protected-payload input for one event occurrence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionError {
    /// Two supplied payloads used the same stable key.
    DuplicatePayload,
    /// A protected event reference had no supplied bytes.
    MissingPayload,
    /// Supplied bytes did not correspond to an event reference.
    UnreferencedPayload,
    /// Supplied bytes and the event envelope disagreed on permission class.
    ClassMismatch,
}

impl fmt::Display for ProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DuplicatePayload => "protected payload key is duplicated",
            Self::MissingPayload => "protected event reference has no payload",
            Self::UnreferencedPayload => "protected payload is absent from the event envelope",
            Self::ClassMismatch => "protected payload class differs from its event reference",
        })
    }
}

impl std::error::Error for ProjectionError {}
