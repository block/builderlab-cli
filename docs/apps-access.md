# Guard an access replacement against concurrent edits

`bl apps access get APP_ID` returns the current policy. On servers that support
revision protection, it also returns `access_revision`. Pass that exact revision
when replacing the policy:

```sh
bl apps access set APP_ID --visibility restricted --viewer 'EXACT_SUBJECT' --expected-revision 7
```

The revision in this example is illustrative: use the value returned for your
app and environment. Replacement still requires the complete intended viewer
list. To clear a restricted list, use the existing `--clear-viewers` option.

The CLI checks the server contract before sending a guarded update. If
`access_policy.expected_revision` is absent or false, it fails without sending
the update. If another edit wins, the server returns a conflict; read access
again and review the new policy before retrying. The CLI does not retry the
replacement or fall back to an unguarded request.

Omitting `--expected-revision` preserves the legacy replacement behavior.
This option is concurrency protection for the existing low-level command, not
recipient discovery or a customer grant/revoke experience. It does not verify
that a supplied subject belongs to an existing account.
