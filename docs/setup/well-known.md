# .well-known configuration

A `.well-known/matrix/client` file is required to be served to allow clients to discover the authentication service.

If no `.well-known/matrix/client` file is served currently then this will need to be enabled.

If the homeserver is Synapse and serving this file already then the correct values will already be included when the homeserver is [configured to use MAS](./homeserver.md).

If the .well-known is hosted elsewhere then `org.matrix.msc2965.authentication` entries need to be included similar to the following:

```json
{
  "m.homeserver": {
    "base_url": "https://matrix.example.com"
  },
  "org.matrix.msc2965.authentication": {
    "issuer": "https://example.com/",
    "account": "https://auth.example.com/account"
  }
}
```

Any Element Web clients configured with a `"default_server_config"` will not look up `.well-known/matrix/client` from the homeserver. So, that configuration needs to include the same `org.matrix.msc2965.authentication` entries as what is served by the homeserver.

For more context on what the correct values are, see [here](./).
