#!/usr/bin/env sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) Alingan Patra
#
# Fails if any tracked source file lacks the SPDX and copyright header.
set -eu
missing=$(git ls-files '*.rs' '*.toml' '*.sh' '*.yml' '*.yaml' | while read -r f; do
  head -n 5 "$f" | grep -q 'SPDX-License-Identifier: Apache-2.0' &&
  head -n 5 "$f" | grep -q 'Copyright (c) Alingan Patra' || echo "$f"
done)
if [ -n "$missing" ]; then
  echo "Missing SPDX/copyright header:"; echo "$missing"; exit 1
fi
echo "SPDX headers OK"
