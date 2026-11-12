# Server 2025 online clone configuration: completed v3 matrix

All ten ordered cases passed, and the host reached terminal success at
2026-11-12T23:29:44.2841189Z. The matrix contains missing-group SDK/reference rejection,
direct membership setup, excluded-application SDK/reference rejection, SDK
online generation, SDK and reference existing-file rejection, reference online
generation, and membership removal. Every child and all three host jobs have
known completion, with no recorded uncertainty or error.

The SDK returned its typed existing-output error on the second online call.
Both SDK and reference collision checks left the existing file's bytes,
timestamps and ACL unchanged. The generated SDK and reference XML files both
validate against the captured Microsoft schema and match in namespace, order
and values. Their formatting bytes differ; byte-for-byte parity is not claimed.

Final evidence verifies removal of both owned cloning files and direct group
membership, restoration of the original 28 exclusions, and matching original
membership views on both DCs. No VM was cloned or restarted. Guest staging and
original host evidence are preserved.

Executed SDK source was 59346e9641feada4915a3313273ee2fc845bdbeb, the reviewed PR83 head subsequently squash
merged as 90f22fe9558f02c93fd9f8a1fb1a9ba306e05d77. The source commit recorded here
is the commit actually archived and built, not a substituted merge commit.
The helper executable SHA-256 is 09D8A615CB80502E707D4F2113315CE619B2B2DBBCEF79501F2CD5FD374F7957. This build includes the
LDAP cursor thread-ownership fix. The prior failed-v1 and failed-v2 attempts
and their separate recoveries remain unchanged in the parent directory.

This qualifies the recorded Server 2025 matrix, not all of issue #55. Other
roles, supported versions, restricted access, nested groups, prerequisite
failures, path aliases and concurrent publication still require separate
evidence. Coverage qualification states were not promoted by this import.

The import independently checks all 133 raw captures against their
digests and original capture envelope, per-case results against raw child
streams, both XML documents against the retained schema, and final restoration
against the original baseline. Import-audit.json lists every copied artifact.
Verified transport envelopes, source archive and executable remain on H: with
their original paths and hashes recorded. Go snapshots use .go.txt filenames;
.gitattributes preserves captured bytes and original trailing blank lines.
The importer loads only pinned validation function ASTs and never executes a
lab harness or changes AD, VM state, ticket state or qualification metadata.