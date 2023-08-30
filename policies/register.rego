# METADATA
# schemas:
#   - input: schema["register_input"]
package register

import data.email as email_policy
import data.password as password_policy

import future.keywords.in

default allow := false

allow {
	count(violation) == 0
}

violation[{"field": "username", "msg": "username too short"}] {
	count(input.username) <= 2
}

violation[{"field": "username", "msg": "username too long"}] {
	count(input.username) >= 15
}

violation[object.union({"field": "password"}, v)] {
	# Check if the registration method is password
	input.registration_method == "password"

	# Get the violation object from the password policy
	some v in password_policy.violation
}

# Check if the email is valid using the email policy
# and add the email field to the violation object
violation[object.union({"field": "email"}, v)] {
	# Get the violation object from the email policy
	some v in email_policy.violation
}
