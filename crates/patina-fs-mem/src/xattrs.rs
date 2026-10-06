//! Extended attribute targets and namespace permission checks.

use crate::metadata::denied;
use crate::namespace::{normalize_entry_path, not_found};
use crate::{InodeId, MemFs};
use patina_dst_abi::{EffectError, ErrorCode, FsEntryKind, XattrTarget};
use patina_dst_driver_api::{DriverResult, XattrNamespace, xattr_permission};

/// Is an attribute access a read or a write (`MAY_READ`/`MAY_WRITE`)?
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum XattrAccess {
    Read,
    Write,
}

/// A missing extended attribute (`ENODATA`).
pub(super) fn no_xattr(name: &str) -> EffectError {
    EffectError::new(
        ErrorCode::NoData,
        format!("virtual extended attribute does not exist: {name}"),
    )
}

impl MemFs {
    /// The node an attribute operation names, and its kind and mode.
    pub(super) fn xattr_node(
        &self,
        target: &XattrTarget,
    ) -> DriverResult<(InodeId, FsEntryKind, u32)> {
        match target {
            XattrTarget::Path(path) => {
                let path = normalize_entry_path(path)?;
                self.resolve_guard(&path)?;
                let metadata = self.metadata_for_path(&path)?;
                Ok((metadata.ino, metadata.kind, metadata.mode))
            }
            XattrTarget::Fd(fd) => {
                let description = self.description(*fd)?;
                if description.path_only {
                    return Err(EffectError::new(
                        ErrorCode::InvalidHandle,
                        format!("virtual handle {} names a location", fd.0),
                    ));
                }
                let (node, kind) = (description.node, description.kind);
                let metadata = if kind == FsEntryKind::Directory {
                    let path = self
                        .node_path(node, kind)
                        .ok_or_else(|| not_found("<removed directory>"))?;
                    self.metadata_for_path(&path)?
                } else {
                    self.metadata_for_inode(node)?
                };
                Ok((node, metadata.kind, metadata.mode))
            }
            XattrTarget::Inode(ino) => {
                let metadata = self.metadata_for_inode(*ino)?;
                Ok((*ino, metadata.kind, metadata.mode))
            }
        }
    }

    /// The kernel's judgment of the access ([`xattr_permission`], one judge for
    /// every filesystem), then the handler lookup `xattr_resolve_name` does
    /// here: a name in no namespace, or in `system.*` (no ACL handler on this
    /// volume), has none, and a namespace prefix alone names nothing.
    pub(super) fn check_xattr(
        kind: FsEntryKind,
        mode: u32,
        name: &str,
        access: XattrAccess,
    ) -> DriverResult<XattrNamespace> {
        let file_or_directory = matches!(kind, FsEntryKind::File | FsEntryKind::Directory);
        let namespace =
            xattr_permission(file_or_directory, mode, name, access == XattrAccess::Write).map_err(
                |code| match code {
                    ErrorCode::Denied => denied(name, "access the extended attribute"),
                    code => EffectError::new(
                        code,
                        format!(
                            "virtual extended attribute {name} is not available to this caller"
                        ),
                    ),
                },
            )?;
        if matches!(namespace, XattrNamespace::System | XattrNamespace::Unknown) {
            return Err(EffectError::new(
                ErrorCode::Unsupported,
                format!("no virtual extended attribute handler for {name}"),
            ));
        }
        let suffix = name.split_once('.').map_or("", |(_, suffix)| suffix);
        if suffix.is_empty() {
            return Err(EffectError::new(
                ErrorCode::InvalidInput,
                format!("virtual extended attribute name has no suffix: {name}"),
            ));
        }
        Ok(namespace)
    }
}

#[cfg(test)]
mod tests;
