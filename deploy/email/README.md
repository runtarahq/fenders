# Workspace invitation email

The Rust customer control plane sends invitations over SMTP with mandatory
STARTTLS and certificate verification. The sign-in provider sends verification emails.

On any supported Linux deployment, copy `invitation-email.example.json` to
`/etc/fenders/control/invitation-email.json`, fill in the SMTP login and install
the password at the referenced file. Set both files to `root:fenders-control`
mode `0640`. Keep these files outside Git, artifacts and application secrets.

Check the relay without sending mail or accessing the database:

```sh
sudo -u fenders-control /path/to/fenders-control-plane \
  --invitation-email /etc/fenders/control/invitation-email.json \
  --check-invitation-email
```

Append `--invitation-email /etc/fenders/control/invitation-email.json` to the
existing control-plane service command, preserving its other arguments. Restart
only the control plane after installing the matching binary. Normal startup
applies the additive invitation/outbox schema. The existing scheduler, worker,
resource enforcement and explicit invocation remain unchanged.

Owners invite an email with a workspace/project scope and role in Settings.
Nothing is granted until the recipient signs in with that verified email and
accepts. Invitations expire after seven days and can be revoked or resent. Only
workspace-wide invitations can offer Owner. The inviter must retain owner access
and the workspace must be active when acceptance happens. Existing conflicting
or revoked memberships require an owner to review access rather than an old
invitation replacing them. A repeated decision never reactivates revoked access.

Invitation creation and its queued email commit together. Email delivery retries
up to five times; exhausted delivery appears as failed and an owner can resend
after the one-minute cooldown. SMTP acceptance is shown as Sent, not proof of
inbox delivery. An uncertain SMTP response may cause the same message/link to
arrive more than once; membership acceptance remains transactional and idempotent.
A mail already in flight when revoked may arrive, but its link cannot grant access.
Creation is bounded to 100 invitations per workspace per day.

Customer invitation links contain a record ID, not a bearer credential. Auth0
sign-in and verified recipient email are required to read or decide the request.
Links survive sign-in; opening a link never accepts it or invokes an application.
