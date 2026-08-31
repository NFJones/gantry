//! Reusable contract suite for backend-neutral journal storage adapters.

use std::sync::Arc;

use gantry::host::journal::{
    AcquireJournalOwnerV1, BatchLocalEvidenceId, JournalBatchV1, JournalCommitRequestV1,
    JournalErrorCode, JournalEvidenceReferenceV1, JournalId, JournalOwnerOperationV1,
    JournalOwnershipToken, JournalPayloadKey, JournalPrefixV1, JournalProtectedPayloadV1,
    JournalStorage, ReadJournalPrefixV1, ReleaseJournalOwnerV1, ResolveJournalPayloadV1,
    UnfinalizedEvidenceV1, validate_journal_prefix,
};
use gantry::portable::{IdentityKind, JournalPrefixForm, ProtectedReferenceClass};

/// One stable failure from the reusable journal-storage contract suite.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalContractFailure {
    /// Stable contract case identifier.
    pub case: &'static str,
    /// Bounded machine-readable detail for the failed assertion.
    pub detail: &'static str,
}

/// Runs the common fenced, atomic journal-storage contract suite.
///
/// The supplied adapter must be fresh for the fixed `contract-journal` target.
/// Persistent adapters may isolate that target in a temporary backend. Passing
/// this suite proves only the typed logical storage contract, not physical
/// persistence or power-loss durability.
pub async fn run_journal_storage_contract(
    storage: &dyn JournalStorage,
) -> Result<(), JournalContractFailure> {
    let journal_id = journal_id();
    let first_owner = storage
        .acquire_owner(AcquireJournalOwnerV1 {
            journal_id: journal_id.clone(),
            operation: JournalOwnerOperationV1::Start,
        })
        .await
        .map_err(|_| failure("owner-acquisition", "first owner was rejected"))?;

    let competing = storage
        .acquire_owner(AcquireJournalOwnerV1 {
            journal_id: journal_id.clone(),
            operation: JournalOwnerOperationV1::Resume,
        })
        .await;
    if competing.map(|_| ()).map_err(|error| error.code)
        != Err(JournalErrorCode::OwnershipUnavailable)
    {
        return Err(failure(
            "owner-acquisition",
            "a competing owner did not lose linearly",
        ));
    }

    let first_batch = JournalBatchV1::new(
        vec![
            body("root", &[], &["payload"]),
            body(
                "child",
                &[JournalEvidenceReferenceV1::BatchLocal(local("root"))],
                &[],
            ),
        ],
        vec![payload("payload", b"secret")],
    )
    .map_err(|_| failure("atomic-commit", "valid batch construction failed"))?;
    let receipt = storage
        .commit(JournalCommitRequestV1 {
            journal_id: journal_id.clone(),
            ownership_token: first_owner.token.clone(),
            batch: first_batch,
        })
        .await
        .map_err(|_| failure("atomic-commit", "valid batch commit failed"))?;
    if receipt.first_sequence != 1
        || receipt.last_sequence != 2
        || receipt.entries.len() != 2
        || receipt.entries[0].sequence != 1
        || receipt.entries[1].sequence != 2
        || receipt.entries[0].evidence_id == receipt.entries[1].evidence_id
        || receipt
            .entries
            .iter()
            .any(|entry| entry.evidence_id.kind() != IdentityKind::Evidence)
    {
        return Err(failure(
            "atomic-commit",
            "receipt identities or contiguous sequences differ",
        ));
    }

    let prefix = storage
        .read_prefix(ReadJournalPrefixV1 {
            journal_id: journal_id.clone(),
        })
        .await
        .map_err(|_| failure("prefix-read", "authoritative read failed"))?;
    validate_journal_prefix(&prefix)
        .map_err(|_| failure("prefix-read", "authoritative prefix is malformed"))?;
    let JournalPrefixV1::Full(prefix) = prefix else {
        return Err(failure(
            "prefix-read",
            "fresh model did not return a full prefix",
        ));
    };
    if prefix.committed_through != 2
        || prefix.evidence.len() != 2
        || prefix.evidence[0].sequence != 1
        || prefix.evidence[1].sequence != 2
        || prefix.evidence[1].references.as_ref() != [receipt.entries[0].evidence_id]
        || prefix
            .evidence
            .iter()
            .any(|entry| entry.journal_id != journal_id)
    {
        return Err(failure(
            "prefix-read",
            "full prefix is not the committed contiguous history",
        ));
    }

    let resolved = storage
        .resolve_payload(ResolveJournalPayloadV1 {
            journal_id: journal_id.clone(),
            key: payload_key("payload"),
        })
        .await
        .map_err(|_| failure("payload-resolution", "stored payload was not resolved"))?;
    if resolved.class != ProtectedReferenceClass::RawOutput || resolved.bytes.as_ref() != b"secret"
    {
        return Err(failure(
            "payload-resolution",
            "resolved payload changed class or bytes",
        ));
    }

    let continuation = JournalBatchV1::new(
        vec![body(
            "continuation",
            &[JournalEvidenceReferenceV1::Existing(
                receipt.entries[1].evidence_id,
            )],
            &["payload"],
        )],
        vec![payload("payload", b"secret")],
    )
    .map_err(|_| failure("idempotent-payload", "continuation construction failed"))?;
    let continuation_receipt = storage
        .commit(JournalCommitRequestV1 {
            journal_id: journal_id.clone(),
            ownership_token: first_owner.token.clone(),
            batch: continuation,
        })
        .await
        .map_err(|_| failure("idempotent-payload", "idempotent payload commit failed"))?;
    if continuation_receipt.first_sequence != 3 || continuation_receipt.last_sequence != 3 {
        return Err(failure(
            "idempotent-payload",
            "continuation did not receive the next sequence",
        ));
    }

    let before_rejections = committed_through(storage, &journal_id).await?;
    for (case, batch, expected) in [
        (
            "duplicate-local-id",
            JournalBatchV1::new(
                vec![body("same", &[], &[]), body("same", &[], &[])],
                Vec::new(),
            )
            .map_err(|_| failure("duplicate-local-id", "fixture construction failed"))?,
            JournalErrorCode::InvalidBatch,
        ),
        (
            "unresolved-local-reference",
            JournalBatchV1::new(
                vec![body(
                    "unresolved",
                    &[JournalEvidenceReferenceV1::BatchLocal(local("missing"))],
                    &[],
                )],
                Vec::new(),
            )
            .map_err(|_| failure("unresolved-local-reference", "fixture construction failed"))?,
            JournalErrorCode::InvalidBatch,
        ),
        (
            "cyclic-local-reference",
            JournalBatchV1::new(
                vec![
                    body(
                        "left",
                        &[JournalEvidenceReferenceV1::BatchLocal(local("right"))],
                        &[],
                    ),
                    body(
                        "right",
                        &[JournalEvidenceReferenceV1::BatchLocal(local("left"))],
                        &[],
                    ),
                ],
                Vec::new(),
            )
            .map_err(|_| failure("cyclic-local-reference", "fixture construction failed"))?,
            JournalErrorCode::InvalidBatch,
        ),
        (
            "payload-conflict",
            JournalBatchV1::new(
                vec![body("conflict", &[], &["payload"])],
                vec![payload("payload", b"different")],
            )
            .map_err(|_| failure("payload-conflict", "fixture construction failed"))?,
            JournalErrorCode::PayloadConflict,
        ),
    ] {
        let result = storage
            .commit(JournalCommitRequestV1 {
                journal_id: journal_id.clone(),
                ownership_token: first_owner.token.clone(),
                batch,
            })
            .await;
        if result.map(|_| ()).map_err(|error| error.code) != Err(expected) {
            return Err(failure(case, "invalid batch was not rejected exactly"));
        }
        if committed_through(storage, &journal_id).await? != before_rejections {
            return Err(failure(case, "rejected batch changed authoritative state"));
        }
    }

    let wrong_token = JournalOwnershipToken::new("wrong-token")
        .map_err(|_| failure("fencing", "wrong-token fixture was invalid"))?;
    let stale_result = storage
        .commit(JournalCommitRequestV1 {
            journal_id: journal_id.clone(),
            ownership_token: wrong_token,
            batch: JournalBatchV1::new(vec![body("stale", &[], &[])], Vec::new())
                .map_err(|_| failure("fencing", "stale fixture construction failed"))?,
        })
        .await;
    if stale_result.map(|_| ()).map_err(|error| error.code) != Err(JournalErrorCode::StaleOwnership)
    {
        return Err(failure("fencing", "stale token was not rejected"));
    }

    storage
        .release_owner(ReleaseJournalOwnerV1 {
            journal_id: journal_id.clone(),
            ownership_token: first_owner.token.clone(),
        })
        .await
        .map_err(|_| failure("owner-release", "current owner release failed"))?;
    let released_result = storage
        .commit(JournalCommitRequestV1 {
            journal_id: journal_id.clone(),
            ownership_token: first_owner.token.clone(),
            batch: JournalBatchV1::new(vec![body("released", &[], &[])], Vec::new())
                .map_err(|_| failure("owner-release", "released fixture construction failed"))?,
        })
        .await;
    if released_result.map(|_| ()).map_err(|error| error.code)
        != Err(JournalErrorCode::StaleOwnership)
    {
        return Err(failure(
            "owner-release",
            "released owner remained authorized",
        ));
    }
    if committed_through(storage, &journal_id).await? != before_rejections {
        return Err(failure(
            "owner-release",
            "owner release changed logical evidence",
        ));
    }

    let second_owner = storage
        .acquire_owner(AcquireJournalOwnerV1 {
            journal_id: journal_id.clone(),
            operation: JournalOwnerOperationV1::Resume,
        })
        .await
        .map_err(|_| failure("owner-reacquisition", "later owner was rejected"))?;
    if second_owner.token == first_owner.token {
        return Err(failure(
            "owner-reacquisition",
            "later owner reused an invalidated fencing token",
        ));
    }
    Ok(())
}

async fn committed_through(
    storage: &dyn JournalStorage,
    journal_id: &JournalId,
) -> Result<u64, JournalContractFailure> {
    let prefix = storage
        .read_prefix(ReadJournalPrefixV1 {
            journal_id: journal_id.clone(),
        })
        .await
        .map_err(|_| failure("prefix-read", "authoritative read failed"))?;
    if prefix.form() != JournalPrefixForm::FullPrefix {
        return Err(failure("prefix-read", "model prefix form changed"));
    }
    match prefix {
        JournalPrefixV1::Full(prefix) => Ok(prefix.committed_through),
        JournalPrefixV1::Snapshot(_) => Err(failure("prefix-read", "model returned a snapshot")),
    }
}

fn journal_id() -> JournalId {
    JournalId::new("contract-journal")
        .unwrap_or_else(|_| unreachable!("constant journal id is nonempty"))
}

fn local(value: &str) -> BatchLocalEvidenceId {
    BatchLocalEvidenceId::new(value.to_owned())
        .unwrap_or_else(|_| unreachable!("fixture local id is nonempty"))
}

fn payload_key(value: &str) -> JournalPayloadKey {
    JournalPayloadKey::new(value.to_owned())
        .unwrap_or_else(|_| unreachable!("fixture payload key is nonempty"))
}

fn body(
    id: &str,
    references: &[JournalEvidenceReferenceV1],
    payloads: &[&str],
) -> UnfinalizedEvidenceV1 {
    UnfinalizedEvidenceV1::new(
        local(id),
        "contract-evidence",
        format!("{{\"id\":\"{id}\"}}").into_bytes(),
        Arc::from(references),
        payloads
            .iter()
            .map(|key| payload_key(key))
            .collect::<Vec<_>>(),
    )
    .unwrap_or_else(|_| unreachable!("fixture evidence fields are nonempty"))
}

fn payload(key: &str, bytes: &[u8]) -> JournalProtectedPayloadV1 {
    JournalProtectedPayloadV1 {
        key: payload_key(key),
        class: ProtectedReferenceClass::RawOutput,
        bytes: Arc::from(bytes),
    }
}

const fn failure(case: &'static str, detail: &'static str) -> JournalContractFailure {
    JournalContractFailure { case, detail }
}
