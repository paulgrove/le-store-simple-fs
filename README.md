# le-store-simple-fs

Stores the account and certificates data in two files:

* `{path}/accounts.json`
* `{path}/certificates.json`

Uses `MongoPortable` to write to and query the files, though manual edits,
should be easy enough if required.

Supports only one option `path` which will be the directory that the files are
stored in.  Please not that this path cannot be `/` (root).

Unlike `le-store-certbot` certificate files are not created as such the
certificates must be extracted to be used.
