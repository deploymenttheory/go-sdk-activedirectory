# Coverage burn-down handoff

The state of the qualification programme, the mechanics needed to add to it, and the
measured facts that are expensive to re-derive. A snapshot of this document is issue #159,
which every open ticket's status comment points at; **this file is the canonical copy** and
should be updated by PR as the work moves.

## 1. The objective, in the owner's words

> "the objective is to have an sdk that's good enough to build on. the plan is to
> build a terraform provider over the top of this sdk."

That sentence decides priorities. When a choice arises between contract
completeness and something a provider would actually hit, the provider wins.

The [SDK v1 readiness gate](sdk-readiness.md), agreed on 2026-11-17, defines
completion across all 151 operation equivalents and the full applicable AD DS
Server 2016/2019/2022/2025 evidence matrix. It adds repeatable lifecycle and
reconciliation requirements while retaining the burn-down order below. The
gate is not met by the aggregate coverage counts alone.

### Standing constraints — do not relitigate these

- **Tickets stay open until evidenced.** Never close one because the code was
  written. A ticket closes when lab evidence exists and the coverage contract
  accepts it.
- **The lab loop:** *"you raise the cmd's in powershell. i approve. that is the
  loop. if i dont prompt me."* Raise the PowerShell command and wait for
  approval. Do not try to route around a permission prompt.
- **Lab permissions are free:** *"add whatever permissions you require for the
  lab. i dont care. it's all throw away anyway."* Grant ACLs, delegate rights,
  create whatever fixtures are needed.
- **Direction decision, 2026-11-17:** the owner was shown that only 2% of recent
  changed lines were shipped code and was offered a pivot to a provider spike.
  The answer was to **continue the scenario burn-down**. Do not re-propose the
  pivot unless asked.

---

## 2. The coverage contract

`coverage/inventory.json` is the single source of truth. 151 operations.

| | states | validated |
| --- | --- | --- |
| behavioural **scenarios** | 1070 | **178** |
| parameter-set **variants** | 253 | **0** |

Validate with `go run ./cmd/adcoverage` → must print
`Coverage contract valid: 151 cmdlets`. The validator is
`internal/coverage/coverage.go`. `-write` regenerates the published report
`docs/coverage.md`; see [coverage-guide.md](coverage-guide.md) for the schema,
the pinned Microsoft source, and `coverage/scenario-requirements.json` (the
separately reviewed manifest of required scenario names — never remove a
requirement to make a partial implementation pass).

### Know this before reporting progress

`docs/coverage.md` says **0 of 151 operations validated**, and it is correct and
in sync. An operation's reported state is the *least advanced* of its parameter
sets **and** its behavioural scenarios. Because all 253 variant states are
`unverified`, **no operation can reach `validated` no matter how many scenario
states land.** The published headline will not move off zero until variants
have passing evidence and their inventory states advance. The variant evidence
policy below is now settled; this decision itself advances no coverage state.

Report progress in scenario states, not operations, and say which. Anyone
reading only `docs/coverage.md` will conclude nothing has happened.

### What a validated scenario requires

Three things on the scenario object, all enforced:

1. `"state": "validated"`
2. `"evidence": ["coverage/lab/.../<file>.json"]`
3. `"implementation": "<a real file path that exists>"` — `validateImplementation`
   stats it. Omitting it fails with `local implementation required`.

And the evidence JSON itself (`validateEvidence`) must have:

- `passed: true`
- `tests[]` — unique, and covering **every** required id for the scenario:
  `<cmdlet>/behavior/<scenario>/success` **and** `/failure`
- `server_version`, `module_version`, `host_version`
- `run` — prose describing what was actually observed

### Variant evidence policy — resolved 2026-11-17

`validateVariants` additionally requires `op.ParameterTests[p]` evidence for
**every parameter** of the variant. All 253 variant states are still
`unverified` and none have ever been advanced.

**Decision:** retain the current bar. Each variant needs its success/failure
evidence and evidence for every parameter, including the validator's requirement
for parameters absent from all syntax sets. Documented Go equivalents of shell
conventions need evidence too. Shared runs may cover multiple claims when each
is actually observed. See the [qualification decision](adr/0001-qualify-the-full-operation-and-version-matrix.md)
and the separate [readiness evidence requirements](sdk-readiness.md#evidence-register-and-release-checklist).
No contract change or coverage promotion follows from this decision.

### Editing the inventory safely

It is ~20k lines of JSON. Patch it in Python and **round-trip check first**, or
the whole file reformats and buries the real change:

```python
raw = io.open('coverage/inventory.json', encoding='utf-8').read()
d = json.loads(raw)
assert json.dumps(d, indent=2, ensure_ascii=False) + '\n' == raw, 'do not patch this way'
# ... mutate d ...
io.open(p,'w',encoding='utf-8',newline='\n').write(json.dumps(d,indent=2,ensure_ascii=False)+'\n')
```

Insert `implementation` **after** `evidence` so key order matches the validated
siblings: `name, description, parameters, prerequisites, expected, state, tests,
evidence, implementation`. Verify with `git diff --stat` — a correct patch
touches tens of lines, not thousands.

Always `assert` before writing, so a failed match writes nothing. This has
already saved the file more than once.

---

## 3. The lab

Hyper-V guests over PowerShell Direct. Domain `ad.sdk.test`, two DCs plus member
`ADSDK25MEM`. State in `H:\ad-sdk-lab\server2025\state.json`, credential in
`credential.clixml` beside it. Helpers in `scripts/lab/guest.ps1`
(`Wait-LabGuest`).

**No elevation.** `BUILTIN\Hyper-V Administrators` is **not** UAC-filtered.
Never use `Start-Process -Verb RunAs`; invoke scripts directly. A
`#Requires -RunAsAdministrator` line on a runner is wrong and was removed.

### Running one harness

Build the test binary, open a session, copy binary + collector, run, copy
artifacts back to `H:\ad-sdk-lab\captures\<stamp>-<name>`. Working example:
`scratchpad/run-accountvalues.ps1`. It mirrors the step in
`scripts/lab/run-reference-batch.ps1` deliberately, so the batch driver and the
one-off runner cannot disagree about how a harness is invoked.

### Collectors

`scripts/lab/reference-*.ps1`, one per family, every one wired into
`run-reference-batch.ps1` behind `-AllowFixtureCreation`. A collector must:

- verify the test binary hash against `-ExpectedHash`
- refuse to run unless `-AllowWrites`
- refuse to start if a fixture root for this run already exists
- **verify cleanup independently of the harness's own claim**, searching for the
  fixture prefix **and** the object prefix, including `sAMAccountName`

That last point is not theoretical. A collector that searched only fixture roots
once reported a clean directory while four strays sat in `CN=Users` and
`CN=Computers`. Both halves are now required. The account-values collector adds
a search by `servicePrincipalName` value, because SPNs are unique forest-wide
and a stray one makes the *next* run's uniqueness probe fail against a leftover
rather than against the object created for it.

---

## 4. The harness pattern

Two files per family, and the second is not optional.

### `activedirectory/acceptance/integration_directory_<family>_windows_test.go`

- build tag `//go:build windows && (amd64 || arm64)`
- gated on `ADSDK_<FAMILY>_ENDPOINT`; `t.Skip` without it so `go test ./...`
  stays clean, and `t.Fatal` if `ADSDK_<FAMILY>_ALLOW_WRITES != "yes"`
- writes exactly one JSON artifact, with `os.O_EXCL` so a run cannot overwrite
  another's result
- creates **one** organizational unit fixture root, removes it in a `defer`, and
  proves removal (`AbsentAfter` **and** an independent `lifecycleAbsent`)
- fixture roots must be OUs — an `organizationalUnit` cannot be created inside a
  `container` (LDAP 64)

### `activedirectory/acceptance/directory_<family>_logic_windows_test.go`

The `qualifies()` aggregation only ever executes inside the lab, so **these
tests are the only place it can be falsified.** Required shape:

- a `passing<X>Observation()` fixture that qualifies
- one subtest per field, mutating it and asserting the observation no longer
  qualifies
- for any error class recorded, a table rejecting every class that would mean
  something else happened (a `denied` is permissions, an `uncertain` means the
  write may have landed — neither evidences a constraint)
- where a slice is aggregated, a test that **every** element is load-bearing,
  not just the first

Current count: 53 subtests over 13 aggregation tests for account-values alone.

### Reusable helpers — use these, do not re-invent

From `activedirectory/acceptance/integration_directory_lifecycle_windows_test.go`:
`lifecycleTargets()` (the shared 5-class table driving six harnesses so they
cannot drift), `lifecycleClass`, `lifecycleDetail`, `lifecycleWhy`,
`lifecycleValues`, `lifecycleAbsent`, `lifecycleRawValues`, `lifecycleVersion`,
and the constants `lifecycleMultiValued` / `lifecycleSingle` /
`lifecycleUndefined`.

From the write sweeps: `writeEndpointRole` + `writeRoleCreate/Update/Delete/Rename`,
`writeCapabilityObservation` (reusable whole, as the rename harness does),
`writeRefusal`.

From account-values: `accountValueRaw` (unsorted, unconverted — a byte-exact
claim cannot be made against `lifecycleValues`, which sorts and stringifies),
`accountValueDigests`, `accountValueText`, `accountValueSorted`,
`accountValueStateName`, `directoryRefusal`, `spnSemantics`.

**`uSNChanged` is the universal "nothing was written" witness.** It advances on
any write the directory accepted, so an unchanged value is the directory's own
statement that nothing landed. Read it with `lifecycleVersion`.

---

## 5. Measured facts — re-deriving these costs hours

### Directory behaviour

- **A base-scoped search echoes the requested DN as the entry name.** The
  entry's `DistinguishedName` is the *requested* spelling; only the
  `distinguishedName` **attribute** is authoritative. Found 2026-11-17: the
  first attempt at the `TargetDN` fix read the entry name and changed nothing at
  all.
- **.NET `CommonSecurityDescriptor` canonicalizes DACL ACE order** (explicit
  deny, explicit allow, inherited deny, inherited allow). Raw server bytes are
  not canonicalized. **Never verify ACL work through a PowerShell DACL read** —
  it hid a wrong diagnosis of #146 twice. Read raw bytes through the code under
  test.
- `description` is schema-multi-valued but **AD enforces single-value** on user,
  group and computer. Use `extensionName` for multi-value probes (six candidates
  were measured to find it).
- An `organizationalUnit` cannot be created inside a `container` — LDAP 64.
- An under-privileged **computer** create returns **LDAP 19**, not 50. A
  permission problem is not always `ClassDenied`; see `docs/errors.md`.
- SPN owned by another object → **LDAP 19**. SPN value already present →
  **LDAP 20** on the explicit path, refused locally as a duplicate raw value on
  the typed path.
- `accountExpires` uses **both** `0` and `MaxInt64` for never. Clearing writes
  `MaxInt64` and leaves the attribute present.
- Protection ACEs: the parent's `ProtectedFromAccidentalDeletion` reads `False`
  while carrying the ACE, so nothing a provider sees changes (this is why #148
  was closed not-planned, after the owner correctly challenged it).

### SDK behaviour

- **A clear that empties an attribute returns `ErrObjectUnverifiable` by
  design** (#150) — absence is equally what a denied read looks like. A harness
  must accept that reading and prove the effect with a read of its own. Two
  probes bailed on it and cost a lab cycle.
- `ErrObjectVerification` → `ClassUncertain` (readback contradicted);
  `ErrObjectUnverifiable` → `ClassUnverified` (nothing could ever prove it).
  The distinction matters to a provider and is live in #157.
- `validDirectoryText` rejects **only** invalid UTF-8 and NUL. `\x01` is a legal
  name. A NUL escape in Go source emits a raw NUL byte and breaks gofmt — write
  `string(rune(0))`.
- `RawValue` is raw bytes by contract, so a NUL passes straight through the
  generic attribute path. That is correct, not a defect.
- **Zero `Parent` is a documented default, not invalid.** A refusal probe that
  passes a zero parent *creates* objects in `CN=Users` / `CN=Computers`.
- `computerManagedAttribute` rejects raw changes to `sAMAccountName` — the typed
  property is the only door. `computerSAM` appends `$` and rejects `$` / `$$`.
- Only `ServiceAccountProperties` has a typed `ServicePrincipalNames`, and it
  **replaces the whole set**. User and computer have no typed SPN writer.
- `UserProperties` has **no** `Country` or `LogonWorkstations` — those need
  explicit attribute changes (`co`, `userWorkstations`).

### Tooling traps

- `gofmt -l .` lists **every file** in the repo (CRLF checkout). Not a signal.
  Check individual files.
- **IDE/LSP diagnostics in this repo are stale** and routinely flag symbols that
  compile fine (`ClassUnverified`, `parseInt64`, `lifecycleDetail`). Trust
  `go build ./...`, `go vet ./...` and `go test -c ./activedirectory/acceptance`.
- Bash heredocs mangle large Go files. Use the Write tool.
- Native Windows Python cannot read MSYS `/c/...` paths; pass Windows paths.
- `gh issue edit --body-file <missing>` reports success and does nothing.
- The command classifier blocks `Remove-Item` when a credential string appears
  in the same script, and blocks hand-rolled DACL rewrites. Escalate; do not
  work around.
- **Diff a branch against main before assuming a fix shipped.** Commit `d81cc7b`
  never merged — #145 was squash-merged before it was pushed, so a cleanup fix
  and two collector fixes sat on a dead branch.

---

## 6. State of play

### Shipped

Two new APIs: error classification (#141 — `ErrorClass`, `Classify`, 11 classes,
175 classified sentinels, 10 `Is*` predicates, `docs/errors.md`) and identity
round-tripping (#142 — `IdentityForm.String`/`MarshalText`/`UnmarshalText`,
`ParseIdentity`).

Six defect fixes, every one provider-relevant:

| fix | PR | what a provider would have hit |
| --- | --- | --- |
| replication site partial write | #143 | a half-applied change reported as success |
| OU protection ACE scan | #147 | protection read wrong on any real DACL |
| already-exists masked in staged creates | #149 | import/adopt flows misreporting |
| unprovable vs contradicted write | #150 | cannot tell "didn't happen" from "can't prove" |
| `TargetDN` spelling | #158 | **no confirmed apply, ever, on manager/member/managedBy** |
| identity resolution | #136 | wrong object selected |

### Evidence sets

Under `coverage/lab/server2025/`: `lifecycle/`, `write-endpoint/`,
`write-invocation/`, `create-attributes/`, `write-capability/`,
`write-authentication/`, `rename/`, `account-values/`. Each has the raw result,
the collector run, the evidence JSON and a README explaining what was measured
and what is deliberately **not** claimed.

### Merged qualification PRs

- **#156** — rename role (3 states) + a self-caught overclaim correction to #154
- **#158** — `TargetDN` fix + four value-property families (20 states)

Both are merged. PR #160 also merged the canonical handoff into the repository.

---

## 7. What to do next, in order

1. **The 14 remaining account property states.** Flag- and transition-shaped,
   so they want their own harness rather than an extension of account-values:
   `account-flags-and-security-values` (7 principal ops: New/Set ×
   user/computer/service-account, plus Set-ADAccountControl),
   `computer-name-and-domain-join-boundary` (2),
   `group-scope-category-transitions` (2), `password-enable-creation-order` (3).
   `AccountControlPatch` has 13 flags; `UpdateGroupRequest` has `Category`/`Scope`
   pointers. Note global↔domain-local is not a legal direct transition.
2. **`protection-acl-preservation`** — 24 states, 12 container classes × New/Set.
   Read the #146/#147 history first, and read raw DACL bytes, not PowerShell's.
3. The large read/update families: `attribute-update-intent` (26),
   `query-scope-paging-and-filters` (24), `selected-and-raw-properties` (17),
   `creation-defaults-and-readback` (14),
   `object-deletion-and-reference-constraints` (14).
4. **`Rename-ADObject` / `authentication-and-permissions`** — the rename role
   needs adding to the write-authentication harness, which owns the restricted
   credential fixture.
5. `ReplicationConnection` Create/Delete (#34).
6. **Variants — retain per-parameter evidence** (section 2); the policy decision
   is settled. Track each claim's Server-version evidence against the readiness
   gate without replacing this scenario burn-down order.

Also open and smaller: #157 (DN normalization reported as uncertain, needs
schema syntax), #140 (two mutation result types omit `ObjectMutationResult`;
re-scoped to documenting and testing the uncertainty-reaches-the-error
contract), #135 (`ErrUnsupported` overloaded).

---

## 8. How to land a family

1. Write the integration harness and the logic test. Run the logic test locally.
2. `go test -c -o tmp/acceptance.test.exe ./activedirectory/acceptance` to confirm
   the windows-tagged files compile on Windows. Ensure `tmp/` exists first.
3. Write the collector; check it parses with
   `[System.Management.Automation.Language.Parser]::ParseFile`.
4. Write a one-off runner in the scratchpad; **raise it in PowerShell and wait
   for approval.**
5. Read the artifact. **Expect to find bugs in your own harness first** — recent
   runs went 6/20 → 18/20 → 20/20, and every one of those failures was the
   harness, not the SDK. Fix and re-run until the measurement is honest.
6. Copy the artifact and collector run into `coverage/lab/server2025/<family>/`,
   write the evidence JSON and a README that states what is **not** claimed.
7. Patch the inventory (section 2). Wire the collector into
   `run-reference-batch.ps1`.
8. `go test ./...`, `golangci-lint run ./...`, `go run ./cmd/adcoverage`.
   Delete any stray `golangci-lint-report.sarif`.
9. Commit, PR, and post a status comment on the ticket. **Do not close it.**

A README that does not say what it fails to prove is not finished. Every evidence
set carries `full_ticket_complete: false` and an explicit "What this is not"
section, and the inventory records `0/253` variants honestly rather than quietly.
