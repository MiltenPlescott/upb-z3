# upb-z3
UPB Zadanie3

# Building
go get .  
go build .  
go run .  

# Details

We use AES128-GCM for encryption with 12 byte nonce. Key derivation function is scrypt with `N=20`, `r=8`, `p=1` parameters and 16 byte salt.    
Format of an encrypted file is as follows: `<salt><nonce><data>`

# Sources

- https://leanpub.com/gocrypto/read
- https://golang.org/src/crypto/cipher/example_test.go
- https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9
- https://blog.filippo.io/the-scrypt-parameters/
