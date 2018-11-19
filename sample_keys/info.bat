@REM Keys generated/converted on commented (@REM) lines are NOT going to work


@REM -----BEGIN GENERATE PRIVATE KEY (KEY PAIR)-----
openssl genrsa -out private.pem 1024
openssl genpkey -out private.der -outform DER -algorithm RSA -pkeyopt rsa_keygen_bits:1024
@REM openssl genpkey -out private.pem -outform PEM -algorithm RSA -pkeyopt rsa_keygen_bits:1024
@REM -----END GENERATE PRIVATE KEY (KEY PAIR)-----


@REM -----BEGIN CONVERT PRIVATE PEM TO DER OR DER TO PEM-----
@REM openssl genpkey PEM is going to work after converting it to DER
openssl rsa -inform PEM -outform DER -in private.pem -out private.der
openssl rsa -inform DER -outform PEM -in private.der -out private.pem
@REM -----END CONVERT PEM TO DER OR DER TO PEM-----


@REM -----BEGIN GENERATE PUBLIC KEY FROM PRIVATE KEY-----
openssl rsa -RSAPublicKey_out -inform PEM -outform PEM -in private.pem -out public.pem
openssl rsa -RSAPublicKey_out -inform DER -outform DER -in private.der -out public.der
@REM openssl rsa -pubout -inform PEM -outform PEM -in private.pem -out public.pem
@REM openssl rsa -pubout -inform DER -outform DER -in private.der -out private.der
@REM -----END GENERATE PUBLIC KEY FROM PRIVATE KEY-----


pause
