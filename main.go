package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "golang.org/x/crypto/scrypt"
    "fmt"
)

// Sizes are in bytes
// We are going to use AES128 for speed, it should be fine
const kAesKeySize = 16
// Recommended by NIST https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
const kAesNonceSize = 12

// https://blog.filippo.io/the-scrypt-parameters/
// According to the article, these are the ideal parameters (for file encryption):
//      N = 2<<20
//      r = 8
//      p = 1
const kScryptSaltSize = 32
// N parameter, 2 << X
const kScryptParamN = 10
const kScryptParamR = 8
const kScryptParamP = 1


func bzero(arr []byte) {
    for i := range arr {
        arr[i] = 0
    }
}

func generateRandomBytes(size int) ([]byte, error) {
    r := make([]byte, size)
    _, err := rand.Read(r)
    return r, err
}

func deriveKey(password, salt []byte) *[kAesKeySize]byte {
    var finalKey = new([kAesKeySize]byte)
    
    // func Key(password, salt []byte, N, r, p, keyLen int) ([]byte, error)
    key, err := scrypt.Key(password, salt, 2 << kScryptParamN, kScryptParamR, kScryptParamP, kAesKeySize)
    if err != nil {
        panic(err.Error())
    }

    copy(finalKey[:], key)
    bzero(key)
    return finalKey
}

func encrypt(key *[kAesKeySize]byte, plain_data []byte) []byte {
    block, err := aes.NewCipher(key[:])
    if err != nil {
        panic(err.Error())
    }

    nonce, err := generateRandomBytes(kAesNonceSize)
    if err != nil {
        panic(err.Error())
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        panic(err.Error())
    }

    encrypted_data := aesgcm.Seal(nil, nonce, plain_data, nil)

    // Prepend the nonce before the encrypted data so we can retrieve it later
    encrypted_data = append(nonce, encrypted_data...)

    return encrypted_data
}

func decrypt(key *[kAesKeySize]byte, encrypted_data []byte) []byte {
    block, err := aes.NewCipher(key[:])
    if err != nil {
        panic(err.Error())
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        panic(err.Error())
    }

    nonce := make([]byte, kAesNonceSize)
    copy(nonce, encrypted_data[:kAesNonceSize])

    data, err := aesgcm.Open(nil, nonce, encrypted_data[kAesNonceSize:], nil)
    if err != nil {
        panic(err.Error())
    }

    return data
}

func main() {
    salt, _ := generateRandomBytes(kScryptSaltSize)
    key := deriveKey([]byte("qwerty"), salt)

    ciphertext := encrypt(key, []byte("Hello encrypted world"))
    fmt.Printf("%x\n", ciphertext)

    plaintext := decrypt(key, ciphertext)
    fmt.Printf("%s\n", plaintext)
}
