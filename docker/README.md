# Docker

Run image from root folder:

    $ docker run --rm --env-file ./config/docker.env -v ${PWD}/config/auth_conf.json:/app/config/auth_conf.json -v ${PWD}/certificates:/app/certificates -p "9065:9065" auth-svc