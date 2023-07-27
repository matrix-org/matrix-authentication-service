This directory contains vendored versions of the compound components, which are not yet published to npm.

 - [`@vector-im/compound-design-tokens`](https://github.com/vector-im/compound-design-tokens)
 - [`@vector-im/compound-web`](https://github.com/vector-im/compound-web)

Installing these dependencies via `git` dependencies was way too slow, so we've vendored them here.

To update them:

 - Clone the above repos
 - Run `yarn` in each
 - Run `npm pack` in each (`yarn pack` skip some files in the tarball)
 - Copy the resulting `vector-im-compound-*.tgz` files into this directory, changing their version with the short commit hash
 - Commit the changes
 - Update the `package.json` to point to the new versions
 - Run `npm install` to update the lockfile