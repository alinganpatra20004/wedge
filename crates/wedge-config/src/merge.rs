// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Alingan Patra

//! Merging of parsed TOML documents (see crate docs for the rules).

use toml::{Table, Value};

/// Merges `overlay` into `base`: tables recurse, arrays append, other values
/// from `overlay` replace those in `base`.
pub(crate) fn merge(base: &mut Table, overlay: Table) {
    for (key, value) in overlay {
        match (base.get_mut(&key), value) {
            (Some(Value::Table(b)), Value::Table(o)) => merge(b, o),
            (Some(Value::Array(b)), Value::Array(o)) => b.extend(o),
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(text: &str) -> Table {
        text.parse().unwrap()
    }

    #[test]
    fn tables_merge_recursively() {
        let mut base = table("[a]\nx = 1\n[a.b]\ny = 2\n");
        merge(&mut base, table("[a.b]\nz = 3\n"));
        assert_eq!(base, table("[a]\nx = 1\n[a.b]\ny = 2\nz = 3\n"));
    }

    #[test]
    fn arrays_append() {
        let mut base = table("v = [1]\n");
        merge(&mut base, table("v = [2, 3]\n"));
        assert_eq!(base, table("v = [1, 2, 3]\n"));
    }

    #[test]
    fn scalars_are_replaced() {
        let mut base = table("x = 1\ny = \"keep\"\n");
        merge(&mut base, table("x = 2\n"));
        assert_eq!(base, table("x = 2\ny = \"keep\"\n"));
    }

    #[test]
    fn type_mismatch_replaces() {
        let mut base = table("x = [1]\n");
        merge(&mut base, table("x = 5\n"));
        assert_eq!(base, table("x = 5\n"));
    }
}
