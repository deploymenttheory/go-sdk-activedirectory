# Full descriptor comparison and cleanup evidence

This directory preserves two root-executed native reference runs for #195.
It does not implement or qualify an SDK atomic NTSD route. See the
[research interpretation and remaining requirements](../../portable-security-descriptor-full-comparison.md).

| Directory | Actual source | Retained result |
| --- | --- | --- |
| `scope-failure-0c641/` | `0c6414e4f76835f05dda9b4e18d2b36702f733a13b05d68a66b755a326d8fd7e` | Private helper child-scope failure before context/provisioning; zero creations/CAS; independent both-DC absence |
| `full15-ddcb6975/` | `ddcb697567cf9345578de34c23b0a59a28e8eaa5994592a226d7338212a2ae80` | Five creates/deletes LDAP0; twelve reads LDAP0; twelve standalone Compare LDAP53; zero CAS; original cleanup flag false, later independent scoped absence true |

Every public JSON/text file and guest-journal record from both exact run
directories is retained byte-for-byte. No private credential file or executable
is included. `sources/` pins both helper versions and exact offline test sources;
`offline/` holds original reviews and all 79-check/eight-check PS5.1/7 receipts.
`research/` retains historical primary findings, proposals and the additive
host-only audit without changing them to fit later outcomes. Proposals are
unexecuted research and do not authorize or perform lab operations.

The later cleanup's unscoped marker search has three referrals and is explicitly
excluded from absence proof. Exact GUID/DN LDAP32 on both DCs plus the critical
`.1339`-scoped zero-entry/zero-reference marker search independently establish
absence. The helper's earlier false cleanup flag remains unchanged.

`artifact-hashes.json` indexes 89 original/tool files. All originals use the
existing `portable-security-descriptor-evidence/** -text` rule. The preservation
tool makes only named public host-file reads and workspace writes; its source
is retained under `tools/`. Historical review paths refer to their original
temporary locations; preserved files can be matched through exact hashes,
including the original pre-append README recovered by recorded length/hash.

The reusable auditor accepts an explicit worktree and either pending
`--working-tree` evidence or committed `--revision <sha>` evidence. It uses
binary `git cat-file --batch` for raw Git verification and compares **all 876
Go/module blobs** with base `0cab072`. Copy it into a task-local directory or
pass `--worktree` when running directly from this retained path:

```text
python tools/audit-atomic-reference.py --worktree <checkout> --revision <commit> --output <fresh-audit.json>
```

The 187-check pending audit passed before commit. This is not an AD capability
promotion. SDK-runtime code, module files, authentication policy and the full
GUID/uSNChanged atomic version contract remain unchanged.

[The committed raw-Git audit](committed-audit-d4eb3fb.json)
passes all 187 evidence/semantic checks and confirms all 876 Go/module blobs
equal base0cab072. This derived receipt points to the first evidence commit;
later audit metadata changes no runtime or original capture.
