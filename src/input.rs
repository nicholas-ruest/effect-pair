use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::{CompareError, EffectEvent};

const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 1_000_000;

#[derive(Debug)]
pub(crate) struct Trace {
    pub events: Vec<EffectEvent>,
    pub digest: String,
}

pub(crate) fn load_trace(path: &Path, kind: &'static str) -> Result<Trace, CompareError> {
    let display_path = path.to_path_buf();
    let bytes = if path.as_os_str() == "-" {
        read_limited(io::stdin().lock(), kind, &display_path)?
    } else {
        let file = File::open(path).map_err(|source| CompareError::ReadTrace {
            kind,
            path: display_path.clone(),
            source,
        })?;
        read_limited(file, kind, &display_path)?
    };
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let text = std::str::from_utf8(&bytes).map_err(|error| CompareError::InvalidTrace {
        kind,
        path: display_path.clone(),
        line: 1,
        message: format!("input is not UTF-8: {error}"),
    })?;
    let mut events = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        if line.trim().is_empty() {
            return Err(CompareError::InvalidTrace {
                kind,
                path: display_path,
                line: line_number,
                message: "blank JSONL records are not allowed".to_owned(),
            });
        }
        if events.len() == MAX_RECORDS {
            return Err(CompareError::TooManyRecords {
                kind,
                path: display_path,
            });
        }
        let event: EffectEvent =
            serde_json::from_str(line).map_err(|error| CompareError::InvalidTrace {
                kind,
                path: display_path.clone(),
                line: line_number,
                message: error.to_string(),
            })?;
        event
            .validate()
            .map_err(|message| CompareError::InvalidTrace {
                kind,
                path: display_path.clone(),
                line: line_number,
                message,
            })?;
        events.push(event);
    }
    Ok(Trace { events, digest })
}

fn read_limited(
    reader: impl Read,
    kind: &'static str,
    path: &Path,
) -> Result<Vec<u8>, CompareError> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| CompareError::ReadTrace {
            kind,
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(CompareError::TraceTooLarge {
            kind,
            path: path.to_path_buf(),
        });
    }
    Ok(bytes)
}
