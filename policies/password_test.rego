package password

test_password_require_number {
	allow with data.passwords.require_number as true

	not allow with input.password as "hunter"
		with data.passwords.require_number as true
}

test_password_require_lowercase {
	allow with data.passwords.require_lowercase as true

	not allow with input.password as "HUNTER2"
		with data.passwords.require_lowercase as true
}

test_password_require_uppercase {
	allow with data.passwords.require_uppercase as true

	not allow with input.password as "hunter2"
		with data.passwords.require_uppercase as true
}

test_password_min_length {
	allow with data.passwords.min_length as 6

	not allow with input.password as "short"
		with data.passwords.min_length as 6
}
