`vaultdb` intends to be a module that provides a mechanism for a database
connection to retrieve ephemeral credentials from a [Hashicorp
Vault](https://www.vaultproject.io/) instance, renewing those credentials as
much as possible, and retrieving new ones when the original ones can no longer
be renewed.

Currently this layers explicitly on top of
[`github.com/lib/pq`](https://github.com/lib/pq), so it only supports Postgres.

It also depends on some packages that have not yet been opened, so it's very
much not useful in its current form.
