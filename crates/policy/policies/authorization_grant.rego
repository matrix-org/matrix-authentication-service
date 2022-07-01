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
	regex.match("urn:matrix:device:[A-Za-z0-9]{10,}", scope)
}

allowed_scope("urn:matrix:api:*") = true

violation[{"msg": msg}] {
	some scope in split(input.authorization_grant.scope, " ")
	not allowed_scope(scope)
	msg := sprintf("scope '%s' not allowed", [scope])
}
