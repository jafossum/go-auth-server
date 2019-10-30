# Simple OAuth 2.0 Server

Basic OAuth 2.0 Authorization Server written in golang
Server is made as a standalone alternative for Auth0 Client Credentials service

https://auth0.com/docs/quickstart/backend

## Running

### Endpoints

#### Authorization Endpoint

To obtain a new Acces Token from the service the `https://YOUR_DOMAIN/oauth/token` endpoint accepts a POST request with the following body
```json
{
    "grant_type": "GRANT_TYPE",
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET",
    "audience": "YOUR_API_IDENTIFIER"
}
```
Currently the server only supports `GRANT_TYPE = client_credentials`.

If client is successfully authenticated, the token response will be the following JSON structure
```json
{
    "token_type": "bearer",
    "access_token": "JWT-TOKEN",
    "expires_in": 3600,
    "refresh_token": "",
    "scope": ""
}
```

#### JWKS Endpoint

To verify the Acces Token, the `https://YOUR_DOMAIN/.well-known/jwks.json` endpoint returns a JSON Web Key Set (JWKS) response form a GET request.
[JSON Web Key Set Properties](https://auth0.com/docs/tokens/reference/jwt/jwks-properties)

### Authorization

For simplicity the authorization is defined by a [`.proto` file](./models/proto/auth.proto). This model definition is generated when running `make`.
The service reads in a `.json` file and parses this into the `.proto` defined structure. See the [auth_config.json](./config/auth_conf.json) file for example.

### Passwords

Passwords are stored in the Authorisation file as bcrypted strings. To create an encrypted string, run `tools/password/encrypt_passwd.go` and follow the instructions.

    $ go run tools/password/encrypt_passwd.go

### TLS

Server is by default expecting to find a TLS `server.key` and `server.cert` in the `./certificate` folder. This folder is gitignored, so this needs to be created, or set the config options to other TLS files. See the `./config` folder

### RSA

JWT token is signed with a RSA256 key-value pair. If a `private.pem` and `public.pem` is provided (defualt `./certificate` folder), this will be used. If no files supplied, or the parsing goes wrong, the service will create its own in-memory keypair for signing. When the service uses the self-generated option, the public key will not be exposed, so this might be the most secure option. See the `./config` folder

## Docker

to Build and run a docker image of the service, see the `docker` folder