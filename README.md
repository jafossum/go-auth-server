# Simple OAuth 2.0 Server

Basic OAuth 2.0 Authorization Server written in golang
Server is made as a standalone alternative for Auth0 Client Credentials service

https://auth0.com/docs/quickstart/backend

## Running

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