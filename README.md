Swiss Vault - Secure Cloud Based Password Manager

[![build](https://github.com/pmoor/swiss-vault/actions/workflows/build.yml/badge.svg)](https://github.com/pmoor/swiss-vault/actions/workflows/build.yml)

## Building

Requires JDK 25 and Maven.

    mvn verify        # unit tests, WAR in target/, then integration tests against a dev server

The integration tests include browser tests (`ClientTest`), which drive Chrome at
`/usr/bin/google-chrome` (override with `-Dchrome.path=...`).

The App Engine SDK (dev server and deploy staging) is fetched from Maven Central
and unpacked into `target/appengine-java-sdk`, so the gcloud `app-engine-java`
component is not needed.

## Client

The client in `src/main/webapp/js` is plain JavaScript (ES modules). `mvn package`
bundles and minifies it into a single `js/app.js` (plus `app.js.map`) with the
Closure Compiler from Maven Central; only the bundle is deployed. Types are
declared in JSDoc comments and checked by TypeScript, which CI runs and which
needs Node.js locally:

    npx -p typescript@7.0.2 tsc -p tsconfig.json

All encryption happens in the browser (`crypto.js`), the server only ever sees
ciphertext. `src/test/resources/legacy-client-data.json` holds data written by
the original 2012 client; `ClientTest` makes sure it stays readable.

### Upgrading passphrases

Passphrases added since 2026 are stretched with PBKDF2-HMAC-SHA512 (210,000
iterations); older ones with PBKDF2-HMAC-SHA1 (1,000 iterations), shown as
"(legacy)" in the Edit Key dialog. To upgrade one: open "edit" for the key, enter
the passphrase and press "try", add the same passphrase again under "Add
Passphrase", then delete the "(legacy)" encryption. Each user's encryptions are
separate, so everyone sharing a key upgrades their own.

## Running locally

    mvn package
    ./devserver.sh    # http://localhost:8080, uses src/main/resources/development.properties

## Deploying

Production configuration lives in `src/main/resources/production.properties`,
which is not checked in. It needs the same keys as `development.properties`.

    gcloud auth login
    ./deploy.sh       # builds, tests and uploads the version from pom.xml (1.5-SNAPSHOT -> 1-5-snapshot), without promoting it

`https://1-5-snapshot-dot-swiss-vault.appspot.com/` should now redirect to the
Google login page. Logging in only works on the configured `hostname`, so to
really try it out send traffic to it:

    gcloud app services set-traffic default --splits=1-5-snapshot=1 --project=swiss-vault

and to roll back, route traffic to the previous version again (`gcloud app versions list`).
