package authorization_grant

user := {"username": "john"}

client := {"client_id": "client"}

test_standard_scopes {
	allow with input.user as user
		with input.client as client
		with input.scope as ""

	allow with input.user as user
		with input.client as client
		with input.scope as "openid"

	allow with input.user as user
		with input.client as client
		with input.scope as "email"

	allow with input.user as user
		with input.client as client
		with input.scope as "openid email"

	# Not supported yet
	not allow with input.user as user
		with input.client as client
		with input.scope as "phone"

	# Not supported yet
	not allow with input.user as user
		with input.client as client
		with input.scope as "profile"
}

test_matrix_scopes {
	allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:api:*"

	allow with input.user as user
		with input.client as client
		with input.grant_type as "urn:ietf:params:oauth:grant-type:device_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:api:*"

	not allow with input.user as user
		with input.client as client
		with input.grant_type as "client_credentials"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:api:*"
}

test_device_scopes {
	allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd01"

	allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd01-asdasdsa1-2313"

	# Invalid characters
	not allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:device:AABB:CCDDEE"

	not allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:device:AABB*CCDDEE"

	not allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:device:AABB!CCDDEE"

	# Too short
	not allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:device:abcd"

	# Multiple device scope
	not allow with input.user as user
		with input.client as client
		with input.grant_type as "authorization_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd01 urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd02"

	# Allowed with the device code grant
	allow with input.user as user
		with input.client as client
		with input.grant_type as "urn:ietf:params:oauth:grant-type:device_code"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd01"

	# Not allowed for the client credentials grant
	not allow with input.client as client
		with input.grant_type as "client_credentials"
		with input.scope as "urn:matrix:org.matrix.msc2967.client:device:AAbbCCdd01"
}

test_synapse_admin_scopes {
	allow with input.user as user
		with input.client as client
		with data.admin_users as ["john"]
		with input.grant_type as "authorization_code"
		with input.scope as "urn:synapse:admin:*"

	allow with input.user as user
		with input.client as client
		with data.admin_users as ["john"]
		with input.grant_type as "urn:ietf:params:oauth:grant-type:device_code"
		with input.scope as "urn:synapse:admin:*"

	not allow with input.user as user
		with input.client as client
		with data.admin_users as []
		with input.grant_type as "authorization_code"
		with input.scope as "urn:synapse:admin:*"

	not allow with input.user as user
		with input.client as client
		with data.admin_users as []
		with input.grant_type as "urn:ietf:params:oauth:grant-type:device_code"
		with input.scope as "urn:synapse:admin:*"

	allow with input.user as user
		with input.user.can_request_admin as true
		with input.client as client
		with data.admin_users as []
		with input.grant_type as "authorization_code"
		with input.scope as "urn:synapse:admin:*"

	allow with input.user as user
		with input.user.can_request_admin as true
		with input.client as client
		with data.admin_users as []
		with input.grant_type as "urn:ietf:params:oauth:grant-type:device_code"
		with input.scope as "urn:synapse:admin:*"

	not allow with input.user as user
		with input.user.can_request_admin as false
		with input.client as client
		with data.admin_users as []
		with input.grant_type as "authorization_code"
		with input.scope as "urn:synapse:admin:*"

	not allow with input.user as user
		with input.user.can_request_admin as false
		with input.client as client
		with data.admin_users as []
		with input.grant_type as "urn:ietf:params:oauth:grant-type:device_code"
		with input.scope as "urn:synapse:admin:*"
}

test_mas_scopes {
	allow with input.user as user
		with input.client as client
		with input.scope as "urn:mas:graphql:*"

	allow with input.user as user
		with input.client as client
		with data.admin_users as ["john"]
		with input.grant_type as "authorization_code"
		with input.scope as "urn:mas:admin"

	not allow with input.user as user
		with input.client as client
		with data.admin_users as []
		with input.grant_type as "authorization_code"
		with input.scope as "urn:mas:admin"
}
