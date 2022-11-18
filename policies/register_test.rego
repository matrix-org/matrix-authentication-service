package register

mock_user := {"username": "hello", "password": "Hunter2", "email": "hello@staging.element.io"}

test_allow_all_domains {
	allow with input.user as mock_user
}

test_allowed_domain {
	allow with input.user as mock_user
		with data.allowed_domains as ["*.element.io"]
}

test_not_allowed_domain {
	not allow with input.user as mock_user
		with data.allowed_domains as ["example.com"]
}

test_banned_domain {
	not allow with input.user as mock_user
		with data.banned_domains as ["*.element.io"]
}

test_banned_subdomain {
	not allow with input.user as mock_user
		with data.allowed_domains as ["*.element.io"]
		with data.banned_domains as ["staging.element.io"]
}

test_short_username {
	not allow with input.user as {"username": "a", "email": "hello@element.io"}
}

test_long_username {
	not allow with input.user as {"username": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "email": "hello@element.io"}
}

test_password_require_number {
	allow with input.user as mock_user
		with data.passwords.require_number as true

	not allow with input.user as mock_user
		with input.user.password as "hunter"
		with data.passwords.require_number as true
}

test_password_require_lowercase {
	allow with input.user as mock_user
		with data.passwords.require_lowercase as true

	not allow with input.user as mock_user
		with input.user.password as "HUNTER2"
		with data.passwords.require_lowercase as true
}

test_password_require_uppercase {
	allow with input.user as mock_user
		with data.passwords.require_uppercase as true

	not allow with input.user as mock_user
		with input.user.password as "hunter2"
		with data.passwords.require_uppercase as true
}

test_password_min_length {
	allow with input.user as mock_user
		with data.passwords.min_length as 6

	not allow with input.user as mock_user
		with input.user.password as "short"
		with data.passwords.min_length as 6
}
