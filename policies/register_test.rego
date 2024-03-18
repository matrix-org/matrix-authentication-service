package register

mock_registration := {
	"registration_method": "password",
	"username": "hello",
	"password": "Hunter2",
	"email": "hello@staging.element.io",
}

test_allow_all_domains {
	allow with input as mock_registration
}

test_allowed_domain {
	allow with input as mock_registration
		with data.allowed_domains as ["*.element.io"]
}

test_not_allowed_domain {
	not allow with input as mock_registration
		with data.allowed_domains as ["example.com"]
}

test_banned_domain {
	not allow with input as mock_registration
		with data.banned_domains as ["*.element.io"]
}

test_banned_subdomain {
	not allow with input as mock_registration
		with data.allowed_domains as ["*.element.io"]
		with data.banned_domains as ["staging.element.io"]
}

test_email_required {
	not allow with input as {"username": "hello", "registration_method": "password"}
}

test_no_email {
	allow with input as {"username": "hello", "registration_method": "upstream-oauth2"}
}

test_short_username {
	not allow with input as {"username": "a", "registration_method": "upstream-oauth2"}
}

test_long_username {
	not allow with input as {"username": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "registration_method": "upstream-oauth2"}
}

test_invalid_username {
	not allow with input as {"username": "hello world", "registration_method": "upstream-oauth2"}
}

test_password_require_number {
	allow with input as mock_registration
		with data.passwords.require_number as true

	not allow with input as mock_registration
		with input.password as "hunter"
		with data.passwords.require_number as true
}

test_password_require_lowercase {
	allow with input as mock_registration
		with data.passwords.require_lowercase as true

	not allow with input as mock_registration
		with input.password as "HUNTER2"
		with data.passwords.require_lowercase as true
}

test_password_require_uppercase {
	allow with input as mock_registration
		with data.passwords.require_uppercase as true

	not allow with input as mock_registration
		with input.password as "hunter2"
		with data.passwords.require_uppercase as true
}

test_password_min_length {
	allow with input as mock_registration
		with data.passwords.min_length as 6

	not allow with input as mock_registration
		with input.password as "short"
		with data.passwords.min_length as 6
}
