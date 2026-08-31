//! Canonical binary codec for version-one logical-session checkpoints.

use std::collections::BTreeMap;
use std::sync::Arc;

use gantry_core::identity::ProtocolIdentity;
use gantry_core::portable::IdentityKind;
use gantry_core::value::ValueLimits;
use gantry_ir::StructuralPosition;

use super::{
    CanonicalTranscriptV1, LogicalSessionRegistryCheckpointV1, LogicalSessionV1,
    SessionCreationModeV1, SessionEstablishmentV1, SessionRecoveryError,
    validate_session_checkpoint,
};

const MAGIC: &[u8; 8] = b"GNTSSP01";

pub(super) fn encode_session_checkpoint(
    checkpoint: &LogicalSessionRegistryCheckpointV1,
) -> Vec<u8> {
    let mut writer = Writer::default();
    writer.raw(MAGIC);
    writer.identity(checkpoint.execution_id);
    writer.count(checkpoint.sessions.len());
    for (id, session) in &checkpoint.sessions {
        writer.identity(*id);
        writer.optional_identity(session.parent);
        writer.identity(session.root);
        writer.u8(mode_tag(session.mode));
        writer.u8(establishment_tag(session.establishment));
        writer.optional_identity(session.creator_task);
        writer.optional_position(session.creation_site.as_ref());
        writer.optional_u64(session.creation_occurrence);
        writer.bytes(session.transcript.bytes());
        writer.optional_bytes(checkpoint.keys.get(id).map(AsRef::as_ref));
    }
    writer.finish()
}

pub(super) fn decode_session_checkpoint(
    bytes: &[u8],
    limits: ValueLimits,
) -> Result<LogicalSessionRegistryCheckpointV1, SessionRecoveryError> {
    let mut reader = Reader::new(bytes);
    if reader.raw(MAGIC.len())? != MAGIC {
        return Err(SessionRecoveryError::InvalidEncoding);
    }
    let execution_id = reader.identity(IdentityKind::Execution)?;
    let count = reader.count()?;
    let mut sessions = BTreeMap::new();
    let mut keys = BTreeMap::new();
    for _ in 0..count {
        let id = reader.identity(IdentityKind::Session)?;
        let parent = reader.optional_identity(IdentityKind::Session)?;
        let root = reader.identity(IdentityKind::Session)?;
        let mode = read_mode(reader.u8()?)?;
        let establishment = read_establishment(reader.u8()?)?;
        let creator_task = reader.optional_identity(IdentityKind::Task)?;
        let creation_site = reader.optional_position()?;
        let creation_occurrence = reader.optional_u64()?;
        let transcript = CanonicalTranscriptV1::decode(reader.bytes()?, limits)
            .map_err(|_| SessionRecoveryError::InvalidCheckpoint)?;
        if let Some(key) = reader.optional_bytes()? {
            keys.insert(id, Arc::from(key));
        }
        if sessions
            .insert(
                id,
                LogicalSessionV1 {
                    execution_id,
                    id,
                    parent,
                    root,
                    mode,
                    establishment,
                    creator_task,
                    creation_site,
                    creation_occurrence,
                    transcript,
                },
            )
            .is_some()
        {
            return Err(SessionRecoveryError::InvalidEncoding);
        }
    }
    if !reader.is_empty() {
        return Err(SessionRecoveryError::InvalidEncoding);
    }
    let checkpoint = LogicalSessionRegistryCheckpointV1 {
        execution_id,
        sessions,
        keys,
    };
    validate_session_checkpoint(&checkpoint)?;
    if encode_session_checkpoint(&checkpoint) != bytes {
        return Err(SessionRecoveryError::InvalidEncoding);
    }
    Ok(checkpoint)
}

const fn mode_tag(mode: SessionCreationModeV1) -> u8 {
    match mode {
        SessionCreationModeV1::EmbedderRoot => 0,
        SessionCreationModeV1::GantryRoot => 1,
        SessionCreationModeV1::New => 2,
        SessionCreationModeV1::Fork => 3,
    }
}

fn read_mode(tag: u8) -> Result<SessionCreationModeV1, SessionRecoveryError> {
    match tag {
        0 => Ok(SessionCreationModeV1::EmbedderRoot),
        1 => Ok(SessionCreationModeV1::GantryRoot),
        2 => Ok(SessionCreationModeV1::New),
        3 => Ok(SessionCreationModeV1::Fork),
        _ => Err(SessionRecoveryError::InvalidEncoding),
    }
}

const fn establishment_tag(establishment: SessionEstablishmentV1) -> u8 {
    match establishment {
        SessionEstablishmentV1::ResolvedPreflight => 0,
        SessionEstablishmentV1::Separate => 1,
        SessionEstablishmentV1::OperationRequest => 2,
    }
}

fn read_establishment(tag: u8) -> Result<SessionEstablishmentV1, SessionRecoveryError> {
    match tag {
        0 => Ok(SessionEstablishmentV1::ResolvedPreflight),
        1 => Ok(SessionEstablishmentV1::Separate),
        2 => Ok(SessionEstablishmentV1::OperationRequest),
        _ => Err(SessionRecoveryError::InvalidEncoding),
    }
}

#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn raw(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u64(&mut self, value: u64) {
        self.raw(&value.to_be_bytes());
    }

    fn count(&mut self, value: usize) {
        self.u64(u64::try_from(value).unwrap_or(u64::MAX));
    }

    fn bytes(&mut self, value: &[u8]) {
        self.count(value.len());
        self.raw(value);
    }

    fn string(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }

    fn identity(&mut self, value: ProtocolIdentity) {
        self.string(&value.to_string());
    }

    fn optional_identity(&mut self, value: Option<ProtocolIdentity>) {
        self.u8(u8::from(value.is_some()));
        if let Some(value) = value {
            self.identity(value);
        }
    }

    fn optional_position(&mut self, value: Option<&StructuralPosition>) {
        self.u8(u8::from(value.is_some()));
        if let Some(value) = value {
            self.count(value.components().len());
            for component in value.components() {
                self.u64(*component);
            }
        }
    }

    fn optional_u64(&mut self, value: Option<u64>) {
        self.u8(u8::from(value.is_some()));
        if let Some(value) = value {
            self.u64(value);
        }
    }

    fn optional_bytes(&mut self, value: Option<&[u8]>) {
        self.u8(u8::from(value.is_some()));
        if let Some(value) = value {
            self.bytes(value);
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn is_empty(&self) -> bool {
        self.cursor == self.bytes.len()
    }

    fn raw(&mut self, length: usize) -> Result<&'a [u8], SessionRecoveryError> {
        let end = self
            .cursor
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(SessionRecoveryError::InvalidEncoding)?;
        let value = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, SessionRecoveryError> {
        self.raw(1).map(|value| value[0])
    }

    fn u64(&mut self) -> Result<u64, SessionRecoveryError> {
        let bytes: [u8; 8] = self
            .raw(8)?
            .try_into()
            .map_err(|_| SessionRecoveryError::InvalidEncoding)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn count(&mut self) -> Result<usize, SessionRecoveryError> {
        let count =
            usize::try_from(self.u64()?).map_err(|_| SessionRecoveryError::InvalidEncoding)?;
        if count > self.bytes.len().saturating_sub(self.cursor) {
            return Err(SessionRecoveryError::InvalidEncoding);
        }
        Ok(count)
    }

    fn bytes(&mut self) -> Result<&'a [u8], SessionRecoveryError> {
        let length =
            usize::try_from(self.u64()?).map_err(|_| SessionRecoveryError::InvalidEncoding)?;
        self.raw(length)
    }

    fn string(&mut self) -> Result<&'a str, SessionRecoveryError> {
        std::str::from_utf8(self.bytes()?).map_err(|_| SessionRecoveryError::InvalidEncoding)
    }

    fn identity(&mut self, kind: IdentityKind) -> Result<ProtocolIdentity, SessionRecoveryError> {
        ProtocolIdentity::parse_kind(self.string()?, kind)
            .map_err(|_| SessionRecoveryError::InvalidEncoding)
    }

    fn optional_identity(
        &mut self,
        kind: IdentityKind,
    ) -> Result<Option<ProtocolIdentity>, SessionRecoveryError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.identity(kind).map(Some),
            _ => Err(SessionRecoveryError::InvalidEncoding),
        }
    }

    fn optional_position(&mut self) -> Result<Option<StructuralPosition>, SessionRecoveryError> {
        match self.u8()? {
            0 => Ok(None),
            1 => {
                let count = self.count()?;
                let mut components = Vec::new();
                for _ in 0..count {
                    components.push(self.u64()?);
                }
                StructuralPosition::new(components)
                    .map(Some)
                    .map_err(|_| SessionRecoveryError::InvalidEncoding)
            }
            _ => Err(SessionRecoveryError::InvalidEncoding),
        }
    }

    fn optional_u64(&mut self) -> Result<Option<u64>, SessionRecoveryError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.u64().map(Some),
            _ => Err(SessionRecoveryError::InvalidEncoding),
        }
    }

    fn optional_bytes(&mut self) -> Result<Option<&'a [u8]>, SessionRecoveryError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.bytes().map(Some),
            _ => Err(SessionRecoveryError::InvalidEncoding),
        }
    }
}
