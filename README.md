# upb-z3
UPB Zadanie3

# Building
go get .  
go build .  
go run .  

# Details

We use AES128-GCM for encryption with 12 byte nonce. Key derivation function is scrypt with `N=10`, `r=8`, `p=1` parameters and 32 byte salt.    

Format of an encrypted file is as follows: `<salt><nonce><data>`. For encryption, we derive a key from an user-entered passphrase with random salt & nonce. We encrypt the data with AES128-GCM and prepend the encrypted data with the generated salt & nonce. For decryption, we derive the key used for encryption using the user passphrase & salt.

We use AES128 instead of 256 because of speed.

# Details v2

We use AES128-GCM for encryption with 12 byte nonce. Randomly generated AES key is encrypted using asymmetric cryptography.

Format of an encrypted file is as follows: `<encrypted-key><nonce><data>`. For encryption, we generate a random key. We encrypt the data with AES128-GCM, encrypt the AES key using asymmetric cryptography and prepend the encrypted data with the encrypted key & nonce. For decryption, we use user provided private key to decrypt the AES key.

We use AES128 instead of 256 because of speed.

## Asymmetric cryptography
- algorithm: RSA
- standard: PKCS #1
    - PKCS #8 keys are NOT supported!
- padding: OAEP
- random oracle: SHA256
- minimum key size: 656 bits
    - messageLength + 2\*hashOutputLength + 2 = 128/8 + 2*256/8 + 2 = 656 bits (https://tools.ietf.org/html/rfc8017#section-7.1.1)
- key structure: ASN.1
- key file:
    - encoding: DER
    - format: PEM
        - supported header labels: "RSA PRIVATE KEY", "RSA PUBLIC KEY"
    - supported input: PEM or DER

### OpenSSL
- generating key pair:
    - PEM: `genrsa`
    - DER: `genpkey -outform DER`
- extracting public key out of key pair: use `-RSAPublicKey_out` instead of `-pubout`
For more information see [rsa.bat](sample_keys/info.bat)


# Sources

- https://leanpub.com/gocrypto/read
- https://golang.org/src/crypto/cipher/example_test.go
- https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
- https://blog.filippo.io/the-scrypt-parameters/
- https://stackoverflow.com/a/29707204
