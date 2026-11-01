// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OpenEdge Labs

//! Checks that ordinary users cannot replace the service binary (threat
//! model T6.7): wedge.exe, its folder (a DLL planted there would load into
//! the service) and every folder above it (renaming one swaps the whole
//! tree) must be changeable only by SYSTEM, Administrators or
//! TrustedInstaller.
//!
//! The access lists come from Windows PowerShell's `Get-Acl` as SIDs (names
//! are localized); the policy below decides.

use std::path::{Path, PathBuf};

/// Prefix of the error when the check could not run at all.
pub(crate) const UNAVAILABLE: &str = "cannot check folder permissions";

const SYSTEM: &str = "S-1-5-18";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
/// CREATOR OWNER and OWNER RIGHTS stand for the owner, which is checked
/// separately.
const OWNER_SIDS: [&str; 2] = ["S-1-3-0", "S-1-3-4"];

const WRITE_DATA: u32 = 0x2;
const APPEND_DATA: u32 = 0x4;
const DELETE_CHILD: u32 = 0x40;
const DELETE: u32 = 0x1_0000;
const WRITE_DAC: u32 = 0x4_0000;
const WRITE_OWNER: u32 = 0x8_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

/// One allow or deny entry, as Get-Acl reports it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Ace {
    pub(crate) sid: String,
    pub(crate) rights: u32,
    pub(crate) allow: bool,
    /// Applies only to children, not to the object itself.
    pub(crate) inherit_only: bool,
}

/// One file or folder's owner and access list.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Entry {
    pub(crate) path: String,
    pub(crate) owner: String,
    pub(crate) aces: Vec<Ace>,
}

/// Checks `exe`, its folder and every folder above it.
pub(crate) fn check(exe: &Path) -> Result<(), String> {
    let chain: Vec<PathBuf> = exe.ancestors().map(Path::to_path_buf).collect();
    let entries = read(&chain)?;
    let problems = violations(&entries);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "ordinary users could replace the service binary:\n  {}",
            problems.join("\n  ")
        ))
    }
}

fn trusted(sid: &str) -> bool {
    matches!(sid, SYSTEM | ADMINISTRATORS | TRUSTED_INSTALLER) || OWNER_SIDS.contains(&sid)
}

/// The rights that would let someone replace what the service runs, for
/// position `index` in the chain (0 = wedge.exe, 1 = its folder, then the
/// folders above).
fn dangerous(index: usize) -> u32 {
    let always = DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;
    match index {
        0 => always | WRITE_DATA | APPEND_DATA | GENERIC_WRITE,
        // Creating files here plants DLLs; creating folders allows
        // `wedge.exe.local` redirection; deleting children swaps the exe.
        1 => always | WRITE_DATA | APPEND_DATA | DELETE_CHILD | GENERIC_WRITE,
        // Above: renaming this folder, or its child in the chain, swaps
        // the whole tree.
        _ => always | DELETE_CHILD,
    }
}

/// Describes every entry that gives an untrusted account a dangerous right.
pub(crate) fn violations(chain: &[Entry]) -> Vec<String> {
    let mut problems = Vec::new();
    for (index, entry) in chain.iter().enumerate() {
        if !trusted(&entry.owner) {
            problems.push(format!("{} is owned by {}", entry.path, entry.owner));
        }
        let mask = dangerous(index);
        for ace in &entry.aces {
            if ace.allow && !ace.inherit_only && !trusted(&ace.sid) && ace.rights & mask != 0 {
                problems.push(format!(
                    "{} gives {} the rights 0x{:x}",
                    entry.path, ace.sid, ace.rights
                ));
            }
        }
    }
    problems
}

/// Reads the access lists through Windows PowerShell. The paths go in an
/// environment variable, never into the script text.
fn read(paths: &[PathBuf]) -> Result<Vec<Entry>, String> {
    const SCRIPT: &str = "$ErrorActionPreference = 'Stop'; \
        $sid = [System.Security.Principal.SecurityIdentifier]; \
        $out = foreach ($p in ($env:WEDGE_ACL_PATHS -split [char]10)) { \
          $acl = if ([IO.Directory]::Exists($p)) { [IO.Directory]::GetAccessControl($p) } \
                 else { [IO.File]::GetAccessControl($p) }; \
          $aces = foreach ($r in $acl.GetAccessRules($true, $true, $sid)) { \
            [pscustomobject]@{ sid = $r.IdentityReference.Value; \
              rights = [uint32]([int64][int]$r.FileSystemRights -band 4294967295); \
              allow = ($r.AccessControlType -eq 'Allow'); \
              inheritOnly = (([int]$r.PropagationFlags -band 2) -ne 0) } }; \
          [pscustomobject]@{ path = $p; owner = $acl.GetOwner($sid).Value; aces = @($aces) } }; \
        ConvertTo-Json -InputObject @($out) -Depth 4 -Compress";
    let list: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
    let output = std::process::Command::new(crate::service::system32(
        r"WindowsPowerShell\v1.0\powershell.exe",
    ))
    .args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        SCRIPT,
    ])
    .env("WEDGE_ACL_PATHS", list.join("\n"))
    // A PowerShell 7 parent's module path breaks Windows PowerShell 5.1.
    .env_remove("PSModulePath")
    .output()
    .map_err(|e| format!("{UNAVAILABLE}: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{UNAVAILABLE}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    parse(&String::from_utf8_lossy(&output.stdout)).map_err(|e| format!("{UNAVAILABLE}: {e}"))
}

/// Parses the script's JSON.
fn parse(json: &str) -> Result<Vec<Entry>, String> {
    let value: serde_json::Value = serde_json::from_str(json.trim()).map_err(|e| e.to_string())?;
    let text = |v: &serde_json::Value, key: &str| {
        v.get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("missing {key}"))
    };
    value
        .as_array()
        .ok_or("expected a list")?
        .iter()
        .map(|item| {
            let aces = item
                .get("aces")
                .and_then(serde_json::Value::as_array)
                .ok_or("missing aces")?
                .iter()
                .map(|a| {
                    Ok(Ace {
                        sid: text(a, "sid")?,
                        rights: a
                            .get("rights")
                            .and_then(serde_json::Value::as_u64)
                            .and_then(|r| u32::try_from(r).ok())
                            .ok_or("bad rights")?,
                        allow: a
                            .get("allow")
                            .and_then(serde_json::Value::as_bool)
                            .ok_or("bad allow")?,
                        inherit_only: a
                            .get("inheritOnly")
                            .and_then(serde_json::Value::as_bool)
                            .ok_or("bad inheritOnly")?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(Entry {
                path: text(item, "path")?,
                owner: text(item, "owner")?,
                aces,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const USERS: &str = "S-1-5-32-545";
    const AUTHENTICATED: &str = "S-1-5-11";
    const READ_EXECUTE: u32 = 0x1200a9;
    const MODIFY: u32 = 0x1301bf;

    fn ace(sid: &str, rights: u32, inherit_only: bool) -> Ace {
        Ace {
            sid: sid.to_owned(),
            rights,
            allow: true,
            inherit_only,
        }
    }

    fn entry(path: &str, aces: Vec<Ace>) -> Entry {
        Entry {
            path: path.to_owned(),
            owner: ADMINISTRATORS.to_owned(),
            aces,
        }
    }

    /// C:\ as Windows ships it: users may create folders here and get
    /// Modify on what they create (inherit-only), nothing else.
    fn drive_root() -> Entry {
        Entry {
            owner: TRUSTED_INSTALLER.to_owned(),
            ..entry(
                r"C:\",
                vec![
                    ace(ADMINISTRATORS, 0x1f01ff, false),
                    ace(SYSTEM, 0x1f01ff, false),
                    ace(USERS, READ_EXECUTE, false),
                    ace(AUTHENTICATED, MODIFY, true),
                    ace(AUTHENTICATED, APPEND_DATA, false),
                ],
            )
        }
    }

    fn locked() -> Vec<Ace> {
        vec![
            ace(SYSTEM, 0x1f01ff, false),
            ace(ADMINISTRATORS, 0x1f01ff, false),
            ace(USERS, READ_EXECUTE, false),
        ]
    }

    #[test]
    fn installer_locked_folder_under_the_drive_root_passes() {
        let chain = [
            entry(r"C:\wedge\wedge.exe", locked()),
            entry(r"C:\wedge", locked()),
            drive_root(),
        ];
        assert_eq!(violations(&chain), Vec::<String>::new());
    }

    #[test]
    fn folder_inheriting_users_modify_fails() {
        // A folder an administrator made under C:\ without locking it.
        let mut open = locked();
        open.push(ace(AUTHENTICATED, MODIFY, false));
        let chain = [
            entry(r"C:\apps\wedge\wedge.exe", locked()),
            entry(r"C:\apps\wedge", locked()),
            entry(r"C:\apps", open),
            drive_root(),
        ];
        let problems = violations(&chain);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].starts_with(r"C:\apps gives S-1-5-11"));
    }

    #[test]
    fn writable_exe_folder_or_untrusted_owner_fails() {
        let mut planting = locked();
        planting.push(ace(USERS, WRITE_DATA | READ_EXECUTE, false));
        let chain = [
            entry(r"D:\w\wedge.exe", locked()),
            entry(r"D:\w", planting),
            drive_root(),
        ];
        assert_eq!(violations(&chain).len(), 1);
        let mut owned = entry(r"D:\w\wedge.exe", locked());
        owned.owner = "S-1-5-21-1-2-3-1001".to_owned();
        let chain = [owned, entry(r"D:\w", locked()), drive_root()];
        assert!(violations(&chain)[0].contains("is owned by"));
    }

    #[test]
    fn deny_and_inherit_only_entries_are_not_grants() {
        let mut aces = locked();
        aces.push(Ace {
            allow: false,
            ..ace(USERS, MODIFY, false)
        });
        aces.push(ace("S-1-3-0", GENERIC_ALL, true));
        aces.push(ace(USERS, MODIFY, true));
        let chain = [
            entry(r"C:\w\wedge.exe", locked()),
            entry(r"C:\w", aces),
            drive_root(),
        ];
        assert_eq!(violations(&chain), Vec::<String>::new());
    }

    #[test]
    fn parses_get_acl_json() {
        let json = r#"[{"path":"C:\\w","owner":"S-1-5-32-544","aces":[{"sid":"S-1-5-18","rights":2032127,"allow":true,"inheritOnly":false}]}]"#;
        let entries = parse(json).unwrap();
        assert_eq!(entries[0].aces[0].rights, 0x1f01ff);
        assert!(parse("{}").is_err());
    }

    #[test]
    fn reads_real_access_lists() {
        // Runs the real PowerShell query on the system folder, which only
        // TrustedInstaller and administrators may change.
        let root = std::env::var_os("SystemRoot").unwrap();
        let exe = Path::new(&root).join("System32").join("notepad.exe");
        let entries = read(&exe.ancestors().map(Path::to_path_buf).collect::<Vec<_>>()).unwrap();
        assert_eq!(entries.len(), 4);
        assert!(
            violations(&entries).is_empty(),
            "{:?}",
            violations(&entries)
        );
    }

    #[test]
    fn a_users_own_folder_is_refused() {
        // The temp folder belongs to the user running the test.
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("wedge.exe");
        std::fs::write(&exe, "").unwrap();
        let err = check(&exe).unwrap_err();
        assert!(err.starts_with("ordinary users could replace"), "{err}");
    }
}
