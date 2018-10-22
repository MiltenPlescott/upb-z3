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

# Sources

- https://leanpub.com/gocrypto/read
- https://golang.org/src/crypto/cipher/example_test.go
- https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
- https://blog.filippo.io/the-scrypt-parameters/
