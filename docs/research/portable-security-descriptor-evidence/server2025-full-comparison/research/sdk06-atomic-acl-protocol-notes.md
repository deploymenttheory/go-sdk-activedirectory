# SDK-06 atomic ACL route follow-up

Reviewed 2026-11-19. This note adds protocol evidence; it does not qualify a
replacement route or declare the original #195 requirements completed.

Microsoft's [LDAP control catalog](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea)
describes controls reported through RootDSE. The listed expected-entry-count
control affects search results, not an atomic conditional modify. Permissive
modify tolerates duplicate additions and absent removals; it would undermine a
stale-value rejection test. Owner and quota controls concern creation. These
controls do not provide the required ACL compare-and-swap behavior.

The [SD-flags specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/932a7a8d-8c93-4448-8093-c79b7d9ba499)
selects descriptor sections to read or update. It does not define an expected
descriptor/version condition. Preserving owner/group/SACL by selecting DACL
alone is useful, but does not guard another writer's concurrent DACL change.

Microsoft's [DNS directory descriptor procedure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/fb192c0d-664b-4ddd-b490-af241b664f8c)
uses a read/edit/replace sequence. The [AD access-control example](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adod/35bcde29-d055-400c-a8f9-09070ebb4c8c)
likewise submits an updated descriptor through LDAP. Neither procedure is
evidence of atomic old-value checking.

The [descriptor requirements](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/081c41f0-4c8d-4ab0-971d-77ec2504375a)
also describe inherited/explicit ACE handling. Readback can therefore establish
an observed descriptor without proving that an unrelated concurrent update was
preserved.

Inference, scoped to these documents and the existing retained live failures:
none of these alternative controls closes the measured assertion/atomic NTSD
gap. The documented replacement sequences must not be relabelled atomic.
Unsupported critical assertions and actual NTSD delete/add refusals remain
separate measured facts from prior #195 work. A successful gMSA membership
descriptor compare-value operation does not establish NTSD support.

Still required: either establish an applicable supported atomic protocol route
with positive/stale/concurrent tests, or resolve that explicit product constraint
with the owner. Until then keep the feature gate and #195/#176 dependency open;
do not substitute unconditional descriptor replacement or a preflight-only check.
