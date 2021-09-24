# `templates`

Helps customizing templates.

## `templates save <path>`

Save the builtin template in the specified folder.

```console
$ mas-cli templates save ./templates
INFO mas_core::templates: Wrote template path="./templates/login.html"
INFO mas_core::templates: Wrote template path="./templates/register.html"
INFO mas_core::templates: Wrote template path="./templates/index.html"
INFO mas_core::templates: Wrote template path="./templates/reauth.html"
INFO mas_core::templates: Wrote template path="./templates/form_post.html"
INFO mas_core::templates: Wrote template path="./templates/error.html"
INFO mas_core::templates: Wrote template path="./templates/base.html"
```

By default this command won't overwrite existing files, but this behavior can be changed by adding the `--overwrite` flag.

## `templates check <path>`

Check the validity of the templates in the specified folder.
It compiles the templates and then renders them with different contexts.

```console
$ mas-cli templates check ./templates
INFO mas_core::templates: Loading builtin templates
INFO mas_core::templates: Loading templates from filesystem path=./templates/**/*.{html,txt}
INFO mas_core::templates::check: Rendering template name="login.html" context={"csrf_token":"fake_csrf_token","form":{"fields_errors":{},"form_errors":[],"has_errors":false}}
INFO mas_core::templates::check: Rendering template name="register.html" context={"__UNUSED":null,"csrf_token":"fake_csrf_token"}
INFO mas_core::templates::check: Rendering template name="index.html" context={"csrf_token":"fake_csrf_token","current_session":{"active":true,"created_at":"2021-09-24T13:26:52.962135085Z","id":1,"last_authd_at":"2021-09-24T13:26:52.962135316Z","user_id":2,"username":"john"},"discovery_url":"https://example.com/.well-known/openid-configuration"}
...
```

Builtin templates are still loaded by default when running this command, but this can be skipped by adding the `--skip-builtin` flag.
