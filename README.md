# oidctl

This is a simple utility that helps developers work with OpenID Connect (oidc).

## Quickstart

1. Install the utility using `go install`:

```
$ go install github.com/bcwaldon/oidctl
```

Ensure the binary is on your `PATH`.

2. Visit your OIDC Identity Provider (i.e. Google Accounts) and create an OAuth2 client identity. Provide the following redirect URI:

```
http://localhost:8080/authorization-code/callback
```

Retrieve the OAuth2 client ID and secret.

3. Use `oidctl` to issue a token, passing the values generated in the previous step:

```
$ oidctl issue --issuer <X> --client-id <Y> --client-secret <Z>
```

Note that this will start a local web server and open a web browser to drive the OAuth2 authorization flow.
Your OIDC `id_token` will be parsed from the access token, verified against the issuer's published signing keys, then printed to your screen.

## Contributing

Please open issues or submit a PR if you would like to contribute.
