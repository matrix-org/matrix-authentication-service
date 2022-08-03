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

allowed_scope("urn:synapse:admin:*") {
	some user in data.admin_users
	input.user.username == user
}

allowed_scope(scope) {
	regex.match("urn:matrix:org.matrix.msc2967.client:device:[A-Za-z0-9-]{10,}", scope)
}

allowed_scope("urn:matrix:org.matrix.msc2967.client:api:*") = true

violation[{"msg": msg}] {
	some scope in split(input.authorization_grant.scope, " ")
	not allowed_scope(scope)
	msg := sprintf("scope '%s' not allowed", [scope])
}

violation[{"msg": "only one device scope is allowed at a time"}] {
	scope_list := split(input.authorization_grant.scope, " ")
	count({key | scope_list[key]; startswith(scope_list[key], "urn:matrix:org.matrix.msc2967.client:device:")}) > 1
}
