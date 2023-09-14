# Migrating an existing homeserver

One of the design goals of MAS has been to allow it to be used to migrate an existing homeserver to an OIDC-based architecture.

Specifically without requiring users to re-authenticate and that non-OIDC clients continue to work.

Features that are provided to support this include:

- Ability to import existing password hashes from Synapse
- Ability to import existing sessions and devices
- Ability to import existing access tokens
- Ability to import existing upstream IdP subject ID mappings
- Provides a compatibility layer for legacy Matrix authentication

There will be tools to help with the migration process itself. But these aren't quite ready yet.
