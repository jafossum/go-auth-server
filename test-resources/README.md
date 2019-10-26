# Generate PEM keys

Private key

    $ openssl genrsa -out private.pem 2048

Public key

    openssl rsa -in private.pem -outform PEM -pubout -out public.pem
