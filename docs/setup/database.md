# Database configuration

The service uses a [PostgreSQL](https://www.postgresql.org/) database to store all of its state.
Although it may be possible to run with earlier versions, it is recommended to use **PostgreSQL 13** or later.
Connection to the database is configured in the [`database`](../usage/configuration.md#database) section of the configuration file.

## Set up a database

You will need to create a dedicated PostgreSQL database for the service.
The database can run on the same server as the service, or on a dedicated host.
The recommended setup for this database is to create a dedicated role and database for the service.

Assuming your PostgreSQL database user is called `postgres`, first authenticate as the database user with:

```sh
su - postgres
# Or, if your system uses sudo to get administrative rights
sudo -u postgres bash
```

Then, create a postgres user and a database with:

```sh
# this will prompt for a password for the new user
createuser --pwprompt mas_user
createdb --owner=mas_user mas
```

The above will create a user called `mas_user` with a password of your choice, and a database called `mas` owned by the `mas_user` user.

Finally, the [`pgcrypto`](https://www.postgresql.org/docs/current/pgcrypto.html) extension must be enabled in the `mas` database.

```
psql -U mas_user mas
CREATE EXTENSION pgcrypto;
```

## Service configuration

Once the database is created, the service needs to be configured to connect to it.
Edit the [`database`](../usage/configuration.md#database) section of the configuration file to match the database just created:

```yaml
database:
  # Full connection string as per
  # https://www.postgresql.org/docs/13/libpq-connect.html#id-1.7.3.8.3.6
  uri: postgres://<user>:<password>@<host>/<database>

  # -- OR --
  # Separate parameters
  host: <host>
  port: 5432
  username: <user>
  password: <password>
  database: <database>
```

## Database migrations

The service manages the database schema with embedded migrations.
Those migrations need to be run before the service can be started, and every time the service is upgraded.
This is done using the [`database migrate`](../usage/cli/database.md#database-migrate) command:

```sh
mas-cli database migrate
```

It is also possible to run any pending migrations on service start, by setting the `--migrate` option to the [`server`](../usage/cli/server.md#server) command:

```sh
mas-cli server --migrate
```

## Next steps

Once the database is up, the remaining steps are to:

 - [Set up the connection to the homeserver (recommended)](./homeserver.md)
 - [Setup email sending (optional)](../usage/configuration.md#email)
 - [Configure a reverse proxy (optional)](./reverse-proxy.md)
 - [Run the service](./running.md)
