openssl genrsa -out private.1024.pem 1024
openssl genrsa -out private.4096.pem 4096

openssl genpkey -out private.1024.der -outform DER -algorithm RSA -pkeyopt rsa_keygen_bits:1024
openssl genpkey -out private.4096.der -outform DER -algorithm RSA -pkeyopt rsa_keygen_bits:4096

openssl rsa -RSAPublicKey_out -inform PEM -outform PEM -in private.1024.pem -out public.1024.pem
openssl rsa -RSAPublicKey_out -inform PEM -outform PEM -in private.4096.pem -out public.4096.pem

openssl rsa -RSAPublicKey_out -inform DER -outform DER -in private.1024.der -out public.1024.der
openssl rsa -RSAPublicKey_out -inform DER -outform DER -in private.4096.der -out public.4096.der

pause
