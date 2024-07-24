# Contributing

This document aims to get you started with contributing to the Matrix Authentication Service!

# 1. Who can contribute to MAS?

We ask that everybody who contributes to this project signs off their contributions, as explained below.

Everyone is welcome to contribute code to [matrix.org projects](https://github.com/matrix-org), provided that they are willing to license their contributions under the same license as the project itself. We follow a simple 'inbound=outbound' model for contributions: the act of submitting an 'inbound' contribution means that the contributor agrees to license the code under the same terms as the project's overall 'outbound' license - in our case, this is almost always Apache Software License v2 (see [LICENSE](https://github.com/matrix-org/matrix-authentication-service/blob/main/LICENSE)).

In order to have a concrete record that your contribution is intentional and you agree to license it under the same terms as the project's license, we've adopted the same lightweight approach used by the [Linux Kernel](https://www.kernel.org/doc/html/latest/process/submitting-patches.html), [Docker](https://github.com/docker/docker/blob/master/CONTRIBUTING.md), and many other projects: the [Developer Certificate of Origin](https://developercertificate.org/) (DCO). This is a simple declaration that you wrote the contribution or otherwise have the right to contribute it to Matrix:

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
660 York Street, Suite 102,
San Francisco, CA 94110 USA

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

If you agree to this for your contribution, then all that's needed is to include the line in your commit or pull request comment:

```
Signed-off-by: Your Name <your@email.example.org>
```

Git allows you to add this signoff automatically when using the `-s` flag to `git commit`, which uses the name and email set in your `user.name` and `user.email` git configs.

# 2. What do I need?

To get MAS running locally from source you will need:

- [Install Rust and Cargo](https://www.rust-lang.org/learn/get-started)
- [Install Node.js and npm](https://nodejs.org/)
- [Install Open Policy Agent](https://www.openpolicyagent.org/docs/latest/#1-download-opa)

# 3. Get the source

- Clone this repository

# 4. Build and run MAS

- Build the frontend
  ```sh
  cd frontend
  npm ci
  npm run build
  cd ..
  ```
- Build the Open Policy Agent policies
  ```sh
  cd policies
  make
  # OR, if you don't have `opa` installed and want to build through the OPA docker image
  make DOCKER=1
  cd ..
  ```
- Generate the sample config via `cargo run -- config generate > config.yaml`
- Run a PostgreSQL database locally
  ```sh
  docker run -p 5432:5432 -e 'POSTGRES_USER=postgres' -e 'POSTGRES_PASSWORD=postgres' -e 'POSTGRES_DATABASE=postgres' postgres
  ```
- Update the database URI in `config.yaml` to `postgresql://postgres:postgres@localhost/postgres`
- Run the database migrations via `cargo run -- database migrate`
- Run the server via `cargo run -- server -c config.yaml`
- Go to <http://localhost:8080/>

# 5. Learn about MAS

You can learn about the [architecture](architecture.md) and [database](database.md) of MAS here.
