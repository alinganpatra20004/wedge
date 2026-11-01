// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OpenEdge Labs

//! Administrator accounts for the admin listener (threat model T5.13 to
//! T5.16).
//!
//! Passwords are never stored: the users file holds one Argon2id hash per
//! account (`name:$argon2id$...`). Logins use HTTP Basic, checked in a
//! blocking thread with at most two checks at a time, and a client address
//! that fails five times within 15 minutes is locked out for 5 minutes.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use password_hash::{PasswordHash, SaltString};
use tokio::sync::Semaphore;

/// Shortest password accepted, in characters.
pub const MIN_PASSWORD_CHARS: usize = 12;
/// Longest password accepted, in bytes (bounds the hashing work).
pub const MAX_PASSWORD_BYTES: usize = 1024;
/// Longest user name accepted, in bytes.
pub const MAX_USER_BYTES: usize = 64;

/// Failed logins from one address before it is locked out.
const MAX_FAILURES: u32 = 5;
/// Failures older than this are forgotten.
const FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
/// How long a locked-out address waits.
const LOCKOUT: Duration = Duration::from_secs(5 * 60);
/// Addresses tracked at once; beyond this, unknown addresses are refused
/// until entries expire, so the table cannot grow without bound.
const MAX_TRACKED: usize = 4096;
/// Hashes checked at the same time (each takes about 19 MiB and tens of ms).
const MAX_CONCURRENT_CHECKS: usize = 2;

/// OWASP's recommended Argon2id settings: 19 MiB, 2 passes, 1 lane.
const MEMORY_KIB: u32 = 19 * 1024;
const PASSES: u32 = 2;
const LANES: u32 = 1;
/// Upper bounds for hashes read from a users file, so an edited file cannot
/// make each login take gigabytes or minutes.
const MAX_MEMORY_KIB: u32 = 256 * 1024;
const MAX_PASSES: u32 = 10;
const MAX_LANES: u32 = 8;

/// Checks a user name: 1 to 64 ASCII letters, digits, `.`, `_`, `-` or `@`.
pub fn validate_user(name: &str) -> Result<(), String> {
    let valid_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@');
    if name.is_empty() || name.len() > MAX_USER_BYTES || !name.chars().all(valid_char) {
        return Err(format!(
            "user name must be 1 to {MAX_USER_BYTES} characters: letters, digits, '.', '_', '-' or '@'"
        ));
    }
    Ok(())
}

/// Checks a new password's length. The value is never part of the message.
pub fn validate_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!(
            "password must have at least {MIN_PASSWORD_CHARS} characters"
        ));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(format!(
            "password must be at most {MAX_PASSWORD_BYTES} bytes"
        ));
    }
    if password.chars().any(char::is_control) {
        return Err("password must not contain control characters".to_owned());
    }
    Ok(())
}

/// Hashes `password` with Argon2id and a random salt, as a PHC string.
pub fn hash_password(password: &str) -> Result<String, String> {
    validate_password(password)?;
    let params = Params::new(MEMORY_KIB, PASSES, LANES, None).map_err(|e| e.to_string())?;
    let salt = SaltString::generate(&mut password_hash::rand_core::OsRng);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| format!("cannot hash the password: {e}"))
}

/// The accounts from one users file.
pub struct Users {
    /// (name, PHC hash string), in file order.
    entries: Vec<(String, String)>,
}

impl Users {
    /// Parses a users file: `name:hash` lines; blank lines and `#` comments
    /// are skipped. Error messages name the line, never its hash.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut entries: Vec<(String, String)> = Vec::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let at = number.saturating_add(1);
            let (name, hash) = line
                .split_once(':')
                .ok_or_else(|| format!("users file line {at}: expected name:hash"))?;
            validate_user(name).map_err(|e| format!("users file line {at}: {e}"))?;
            check_hash(hash).map_err(|e| format!("users file line {at}: {e}"))?;
            if entries.iter().any(|(n, _)| n == name) {
                return Err(format!("users file line {at}: user {name:?} appears twice"));
            }
            entries.push((name.to_owned(), hash.to_owned()));
        }
        if entries.is_empty() {
            return Err("users file has no accounts".to_owned());
        }
        Ok(Self { entries })
    }

    /// The file text with `name` set to `hash`, replacing an existing entry
    /// or adding one.
    pub fn with_user(text: &str, name: &str, hash: &str) -> String {
        let mut out = String::new();
        let mut replaced = false;
        for line in text.lines() {
            let same = line.trim().split_once(':').is_some_and(|(n, _)| n == name);
            if same {
                if !replaced {
                    out.push_str(&format!("{name}:{hash}\n"));
                    replaced = true;
                }
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        if !replaced {
            out.push_str(&format!("{name}:{hash}\n"));
        }
        out
    }

    /// Number of accounts.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Never true: parsing refuses an empty file.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `password` is the password of `name`. An unknown name is
    /// checked against another account's hash, so both take the same time
    /// and response times do not reveal which names exist.
    fn verify(&self, name: &str, password: &[u8]) -> bool {
        let known = self.entries.iter().find(|(n, _)| n == name);
        let Some((_, hash)) = known.or_else(|| self.entries.first()) else {
            return false;
        };
        let Ok(parsed) = PasswordHash::new(hash) else {
            return false;
        };
        let matches = Argon2::default().verify_password(password, &parsed).is_ok();
        matches && known.is_some()
    }
}

/// Accepts only Argon2id hashes with bounded cost.
fn check_hash(hash: &str) -> Result<(), String> {
    let parsed = PasswordHash::new(hash).map_err(|_| "hash is not a PHC string".to_owned())?;
    if parsed.algorithm.as_str() != "argon2id" {
        return Err("hash must be Argon2id (made by `wedge admin set-password`)".to_owned());
    }
    let params =
        Params::try_from(&parsed).map_err(|_| "hash has invalid Argon2 parameters".to_owned())?;
    if params.m_cost() > MAX_MEMORY_KIB
        || params.t_cost() > MAX_PASSES
        || params.p_cost() > MAX_LANES
    {
        return Err(format!(
            "hash cost is above the limits (m={MAX_MEMORY_KIB}, t={MAX_PASSES}, p={MAX_LANES})"
        ));
    }
    Ok(())
}

/// The outcome of a login attempt.
pub(crate) enum Login {
    /// Valid credentials for this user.
    Ok(String),
    /// Missing or wrong credentials.
    Denied,
    /// Too many failures from this address; retry after this long.
    LockedOut(Duration),
}

/// Failure counts per client address, and the hashing concurrency limit.
/// Lives as long as the server, across reloads.
pub(crate) struct Guard {
    failures: Mutex<HashMap<IpAddr, Failures>>,
    checks: Arc<Semaphore>,
}

struct Failures {
    count: u32,
    first: Instant,
    locked_until: Option<Instant>,
}

impl Guard {
    pub(crate) fn new() -> Self {
        Self {
            failures: Mutex::new(HashMap::new()),
            checks: Arc::new(Semaphore::new(MAX_CONCURRENT_CHECKS)),
        }
    }

    /// Checks the `Authorization` header value against `users`.
    pub(crate) async fn login(
        &self,
        users: &Arc<Users>,
        peer: IpAddr,
        authorization: Option<&[u8]>,
    ) -> Login {
        if let Some(wait) = self.locked(peer) {
            return Login::LockedOut(wait);
        }
        let Some((name, password)) = authorization.and_then(basic_credentials) else {
            // No credentials yet: the browser's first request. Not a failure.
            return Login::Denied;
        };
        let Ok(_permit) = Arc::clone(&self.checks).acquire_owned().await else {
            return Login::Denied;
        };
        let users = Arc::clone(users);
        let user = name.clone();
        let ok = tokio::task::spawn_blocking(move || users.verify(&user, password.as_bytes()))
            .await
            .unwrap_or(false);
        if ok {
            self.forget(peer);
            Login::Ok(name)
        } else {
            tracing::warn!(%peer, user = %name, "admin login failed");
            match self.failed(peer) {
                Some(wait) => Login::LockedOut(wait),
                None => Login::Denied,
            }
        }
    }

    /// Time left on `peer`'s lockout, if it is locked out.
    fn locked(&self, peer: IpAddr) -> Option<Duration> {
        let now = Instant::now();
        let mut table = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        if table.len() >= MAX_TRACKED && !table.contains_key(&peer) {
            table.retain(|_, f| !f.expired(now));
            if table.len() >= MAX_TRACKED {
                return Some(LOCKOUT);
            }
        }
        let until = table.get(&peer)?.locked_until?;
        until.checked_duration_since(now)
    }

    /// Records a failure; returns the lockout if this one triggered it.
    fn failed(&self, peer: IpAddr) -> Option<Duration> {
        let now = Instant::now();
        let mut table = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let entry = table.entry(peer).or_insert(Failures {
            count: 0,
            first: now,
            locked_until: None,
        });
        if entry.expired(now) {
            *entry = Failures {
                count: 0,
                first: now,
                locked_until: None,
            };
        }
        entry.count = entry.count.saturating_add(1);
        if entry.count >= MAX_FAILURES {
            tracing::warn!(%peer, "admin logins locked out for {} s", LOCKOUT.as_secs());
            entry.locked_until = Some(now + LOCKOUT);
            entry.count = 0;
            entry.first = now;
            return Some(LOCKOUT);
        }
        None
    }

    fn forget(&self, peer: IpAddr) {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&peer);
    }
}

impl Failures {
    fn expired(&self, now: Instant) -> bool {
        let lock_over = self.locked_until.is_none_or(|until| now >= until);
        lock_over && now.saturating_duration_since(self.first) >= FAILURE_WINDOW
    }
}

/// Decodes `Basic base64(name:password)`. The password is returned zeroed on
/// drop by the caller's `String`; it is never logged.
fn basic_credentials(header: &[u8]) -> Option<(String, zeroize::Zeroizing<String>)> {
    use base64ct::{Base64, Encoding};
    let (scheme, encoded) = std::str::from_utf8(header).ok()?.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") || encoded.len() > 4 * MAX_PASSWORD_BYTES {
        return None;
    }
    let decoded = zeroize::Zeroizing::new(Base64::decode_vec(encoded.trim()).ok()?);
    let text = std::str::from_utf8(&decoded).ok()?;
    let (name, password) = text.split_once(':')?;
    validate_user(name).ok()?;
    if password.len() > MAX_PASSWORD_BYTES {
        return None;
    }
    Some((
        name.to_owned(),
        zeroize::Zeroizing::new(password.to_owned()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(name: &str, password: &str) -> Vec<u8> {
        use base64ct::{Base64, Encoding};
        format!(
            "Basic {}",
            Base64::encode_string(format!("{name}:{password}").as_bytes())
        )
        .into_bytes()
    }

    #[test]
    fn user_names_are_restricted() {
        assert!(validate_user("admin").is_ok());
        assert!(validate_user("ops.team-1@site").is_ok());
        for bad in ["", "a:b", "a b", "<script>", "ä", &"x".repeat(65)] {
            assert!(validate_user(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn short_or_odd_passwords_are_refused() {
        assert!(validate_password("correct horse").is_ok());
        assert!(validate_password("short").is_err());
        assert!(validate_password("eleven char").is_err());
        assert!(validate_password("twelve chars\nx").is_err());
        assert!(validate_password(&"x".repeat(MAX_PASSWORD_BYTES + 1)).is_err());
    }

    #[test]
    fn hash_round_trip_and_wrong_password() {
        let hash = hash_password("correct horse battery").unwrap();
        assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        let users = Users::parse(&format!("# admins\nadmin:{hash}\n")).unwrap();
        assert!(users.verify("admin", b"correct horse battery"));
        assert!(!users.verify("admin", b"correct horse batterY"));
        // An unknown name never succeeds, even with a valid password.
        assert!(!users.verify("root", b"correct horse battery"));
    }

    #[test]
    fn users_file_errors_name_the_line_not_the_hash() {
        let err = Users::parse("admin:secret-in-clear\n").err().unwrap();
        assert_eq!(err, "users file line 1: hash is not a PHC string");
        assert!(Users::parse("\n# nothing\n").is_err());
        let hash = hash_password("correct horse battery").unwrap();
        let twice = format!("a:{hash}\na:{hash}\n");
        assert!(Users::parse(&twice).err().unwrap().contains("twice"));
        let costly = "a:$argon2id$v=19$m=4194304,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g";
        assert!(Users::parse(costly)
            .err()
            .unwrap()
            .contains("above the limits"));
        let bcrypt = "a:$2b$12$abcdefghijklmnopqrstuuMJo0D3H0xfBNxnF4XyYwqAqyfV9CzcW";
        assert!(Users::parse(bcrypt).is_err());
    }

    #[test]
    fn with_user_replaces_or_appends() {
        let text = "# keep\nadmin:old\nops:x\n";
        assert_eq!(
            Users::with_user(text, "admin", "new"),
            "# keep\nadmin:new\nops:x\n"
        );
        assert_eq!(
            Users::with_user(text, "web", "h"),
            "# keep\nadmin:old\nops:x\nweb:h\n"
        );
        assert_eq!(Users::with_user("", "admin", "h"), "admin:h\n");
    }

    #[test]
    fn basic_header_parsing() {
        let (name, password) = basic_credentials(&basic("admin", "pa:ss word")).unwrap();
        assert_eq!((name.as_str(), password.as_str()), ("admin", "pa:ss word"));
        assert!(basic_credentials(b"Bearer abc").is_none());
        assert!(basic_credentials(b"Basic !!!").is_none());
        assert!(basic_credentials(&basic("bad name", "x")).is_none());
        assert!(basic_credentials(b"Basic").is_none());
    }

    #[tokio::test]
    async fn five_failures_lock_the_address_out() {
        let hash = hash_password("correct horse battery").unwrap();
        let users = Arc::new(Users::parse(&format!("admin:{hash}")).unwrap());
        let guard = Guard::new();
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let other: IpAddr = "127.0.0.2".parse().unwrap();
        let wrong = basic("admin", "wrong password!!");
        let right = basic("admin", "correct horse battery");
        assert!(matches!(
            guard.login(&users, peer, None).await,
            Login::Denied
        ));
        for _ in 0..MAX_FAILURES - 1 {
            assert!(matches!(
                guard.login(&users, peer, Some(&wrong)).await,
                Login::Denied
            ));
        }
        assert!(matches!(
            guard.login(&users, peer, Some(&wrong)).await,
            Login::LockedOut(_)
        ));
        // Locked out: even the right password is refused, without hashing.
        assert!(matches!(
            guard.login(&users, peer, Some(&right)).await,
            Login::LockedOut(_)
        ));
        // Other addresses are not affected.
        assert!(
            matches!(guard.login(&users, other, Some(&right)).await, Login::Ok(ref n) if n == "admin")
        );
    }
}
