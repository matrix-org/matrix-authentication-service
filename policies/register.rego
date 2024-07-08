# METADATA
# schemas:
#   - input: schema["register_input"]
package register

import data.email as email_policy

import future.keywords.in

default allow := false

allow {
	count(violation) == 0
}

violation[{"field": "username", "msg": "username too short"}] {
	count(input.username) <= 2
}

violation[{"field": "username", "msg": "username too long"}] {
	count(input.username) > 64
}

violation[{"field": "username", "msg": "username contains invalid characters"}] {
	not regex.match("^[a-z0-9.=_/-]+$", input.username)
}

violation[{"msg": "unspecified registration method"}] {
	not input.registration_method
}

violation[{"msg": "unknown registration method"}] {
	not input.registration_method in ["password", "upstream-oauth2"]
}

# Check that we supplied an email for password registration
violation[{"field": "email", "msg": "email required for password-based registration"}] {
	input.registration_method == "password"

	not input.email
}

# Check if the email is valid using the email policy
# and add the email field to the violation object
violation[object.union({"field": "email"}, v)] {
	# Check if we have an email set in the input
	input.email

	# Get the violation object from the email policy
	some v in email_policy.violation
}
