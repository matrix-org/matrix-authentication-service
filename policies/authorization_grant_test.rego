package authorization_grant

user := {"username": "john"}

test_standard_scopes {
	allow with input.user as user
		with input.authorization_grant as {"scope": ""}

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
		with input.authorization_grant as {"scope": "urn:matrix:org.matrix.msc2967.client:api:*"}
}

test_device_scopes {
	allow with input.user as user
		with input.authorization_grant as {"scope": "urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd01"}

	allow with input.user as user
		with input.authorization_grant as {"scope": "urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd01-asdasdsa1-2313"}

	# Invalid characters
	not allow with input.user as user
		with input.authorization_grant as {"scope": "urn:matrix:org.matrix.msc2967.client:device:AABB:CCDDEE"}

	not allow with input.user as user
		with input.authorization_grant as {"scope": "urn:matrix:org.matrix.msc2967.client:device:AABB*CCDDEE"}

	not allow with input.user as user
		with input.authorization_grant as {"scope": "urn:matrix:org.matrix.msc2967.client:device:AABB!CCDDEE"}

	# Too short
	not allow with input.user as user
		with input.authorization_grant as {"scope": "urn:matrix:org.matrix.msc2967.client:device:abcd"}

	# Multiple device scope
	not allow with input.user as user
		with input.authorization_grant as {"scope": "urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd01 urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd02"}
}

test_synapse_admin_scopes {
	allow with input.user as user
		with data.admin_users as ["john"]
		with input.authorization_grant as {"scope": "urn:synapse:admin:*"}

	not allow with input.user as user
		with data.admin_users as []
		with input.authorization_grant as {"scope": "urn:synapse:admin:*"}
}

test_mas_scopes {
	allow with input.user as user
		with input.authorization_grant as {"scope": "urn:mas:graphql:*"}

	allow with input.user as user
		with data.admin_users as ["john"]
		with input.authorization_grant as {"scope": "urn:mas:admin"}

	not allow with input.user as user
		with data.admin_users as []
		with input.authorization_grant as {"scope": "urn:mas:admin"}
}
