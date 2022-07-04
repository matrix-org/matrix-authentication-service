package authorization_grant

user := {"username": "john"}

test_standard_scopes {
	allow with input.user as user
		with input.authorization_grant as {"scope": "openid"}

	allow with input.user as user
		with input.authorization_grant as {"scope": "email"}

	allow with input.user as user
		with input.authorization_grant as {"scope": "openid email"}

	# Not supported yet
	not allow with input.user as user
		with input.authorization_grant as {"scope": "phone"}

	# Not supported yet
	not allow with input.user as user
		with input.authorization_grant as {"scope": "profile"}
}

test_matrix_scopes {
	allow with input.user as user
		with input.authorization_grant as {"scope": "urn:matrix:api:*"}
}

test_device_scopes {
	allow with input.user as user
		with input.authorization_grant as {"scope": "urn:matrix:device:AAbbCCdd01"}

	# Invalid characters
	not allow with input.user as user
		with input.authorization_grant as {"scope": "urn:matrix:device:AABB:CCDDEE"}

	# Too short
	not allow with input.user as user
		with input.authorization_grant as {"scope": "urn:matrix:device:abcd"}

	# Multiple device scope
	not allow with input.user as user
		with input.authorization_grant as {"scope": "urn:matrix:device:AAbbCCdd01 urn:matrix:device:AAbbCCdd02"}
}

test_synapse_admin_scopes {
	allow with input.user as user
		with data.admin_users as ["john"]
		with input.authorization_grant as {"scope": "urn:synapse:admin:*"}

	not allow with input.user as user
		with data.admin_users as []
		with input.authorization_grant as {"scope": "urn:synapse:admin:*"}
}
