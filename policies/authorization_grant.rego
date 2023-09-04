# METADATA
# schemas:
#   - input: schema["authorization_grant_input"]
package authorization_grant

import future.keywords.in

default allow := false

allow {
	count(violation) == 0
}

# Special case to make empty scope work
allowed_scope("") = true

allowed_scope("openid") = true

allowed_scope("email") = true

# This grants access to Synapse's admin API endpoints
allowed_scope("urn:synapse:admin:*") {
	input.grant_type == "authorization_code"
	some user in data.admin_users
	input.user.username == user
}

# This grants access to the /graphql API endpoint
allowed_scope("urn:mas:graphql:*") = true

# This makes it possible to query and do anything in the GraphQL API as an admin
allowed_scope("urn:mas:admin") {
	input.grant_type == "authorization_code"
	some user in data.admin_users
	input.user.username == user
}

# This makes it possible to get the admin scope for clients that are allowed
allowed_scope("urn:mas:admin") {
	input.grant_type == "client_credentials"
	some client in data.admin_clients
	input.client.id == client
}

allowed_scope(scope) {
	# Grant access to the C-S API only if there is a user
	input.grant_type == "authorization_code"
	regex.match("urn:matrix:org.matrix.msc2967.client:device:[A-Za-z0-9-]{10,}", scope)
}

allowed_scope("urn:matrix:org.matrix.msc2967.client:api:*") {
	# Grant access to the C-S API only if there is a user
	input.grant_type == "authorization_code"
}

violation[{"msg": msg}] {
	some scope in split(input.scope, " ")
	not allowed_scope(scope)
	msg := sprintf("scope '%s' not allowed", [scope])
}

violation[{"msg": "only one device scope is allowed at a time"}] {
	scope_list := split(input.scope, " ")
	count({key | scope_list[key]; startswith(scope_list[key], "urn:matrix:org.matrix.msc2967.client:device:")}) > 1
}
