package main

import (
    "errors"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "golang.org/x/crypto/scrypt"
    "fmt"
    //"io"
    "os"
    "io/ioutil" // reading/writing files
    "time" // timing encryption/decryption
    "flag" // command line flags
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
const kScryptParamN = 20 // 2 << X
const kScryptParamR = 8
const kScryptParamP = 1


var (
    ErrorEncrypt = errors.New("Encryption failed")
    ErrorDecrypt = errors.New("Decryption failed")
)


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
        fmt.Println(err.Error())
        return nil
    }

    copy(finalKey[:], key)
    bzero(key)
    return finalKey
}

func encrypt(key *[kAesKeySize]byte, plain_data []byte) ([]byte, error) {
    block, err := aes.NewCipher(key[:])
    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorEncrypt
    }

    nonce, err := generateRandomBytes(kAesNonceSize)
    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorEncrypt
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorEncrypt
    }

    encrypted_data := aesgcm.Seal(nil, nonce, plain_data, nil)

    // Prepend the nonce before the encrypted data so we can retrieve it later
    encrypted_data = append(nonce, encrypted_data...)

    return encrypted_data, nil
}

func decrypt(key *[kAesKeySize]byte, encrypted_data []byte) ([]byte, error) {
    block, err := aes.NewCipher(key[:])
    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorDecrypt
    }

    aesgcm, err := cipher.NewGCM(block)
    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorDecrypt
    }

    nonce := make([]byte, kAesNonceSize)
    copy(nonce, encrypted_data[:kAesNonceSize])

    data, err := aesgcm.Open(nil, nonce, encrypted_data[kAesNonceSize:], nil)
    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorDecrypt
    }

    return data, nil
}

func Seal(password, plain_data []byte) ([]byte, error) {
    salt, err := generateRandomBytes(kScryptSaltSize)
    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorEncrypt
    }

    key := deriveKey(password, salt)
    encrypted_data, err := encrypt(key, plain_data)
    bzero(key[:])

    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorEncrypt
    }

    // Prepend encrypted data with salt used to derive the key
    encrypted_data = append(salt, encrypted_data...)
    return encrypted_data, nil
}

func Open(password, encrypted_data []byte) ([]byte, error) {
    // Extract salt from the start of the file
    salt := make([]byte, kScryptSaltSize)
    copy(salt, encrypted_data[:kScryptSaltSize])

    key := deriveKey(password, salt)
    plain_data, err := decrypt(key, encrypted_data[kScryptSaltSize:])
    bzero(key[:])

    if err != nil {
        fmt.Println(err.Error())
        return nil, ErrorDecrypt
    }

    return plain_data, nil
}

func EncryptFile(password []byte, in_path string, out_path string) error {
    data, err := ioutil.ReadFile(in_path)
    if err != nil {
        return err
    }

    encrypted_data, err := Seal(password, data)
    if err != nil {
        return err
    }

    return ioutil.WriteFile(out_path, encrypted_data, 0644)
}

func DecryptFile(password []byte, in_path string, out_path string) error {
    encrypted_data, err := ioutil.ReadFile(in_path)
    if err != nil {
        return err
    }

    plain_data, err := Open(password, encrypted_data)
    if err != nil {
        return err
    }

    return ioutil.WriteFile(out_path, plain_data, 0644)
}

func main() {
    /*
    Example 1: text encryption/decryption with a pre-defined password


    ciphertext, err := Seal([]byte("qwerty"), []byte("Hello encrypted world"))
    if err != nil {
        panic(err.Error())
    }

    fmt.Printf("ciphertext: %x\n", ciphertext)

    plaintext, err := Open([]byte("qwerty"), ciphertext)
    if err != nil {
        panic(err.Error())
    }

    fmt.Printf("plaintext: %s\n", plaintext)
    */

    /*
    Example 2: file encryption/decryption with a pre-defined password
    */
    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "Usage: %s [-d|-e] <in_file> <out_file>\n", os.Args[0])
    }

    decryptFlag := flag.Bool("d", false, "decrypt <in_file> into <out_file>")
    encryptFlag := flag.Bool("e", false, "encrypt <in_file> into <out_file>")
    flag.Parse()

    if flag.NArg() < 2 {
        flag.Usage()
        return
    }

    password := []byte("pleasedontstealourfiles")

    start := time.Now()

    if *decryptFlag && !*encryptFlag {
        err := DecryptFile(password, flag.Arg(0), flag.Arg(1))
        if err != nil {
            panic(err.Error())
        }
    } else if *encryptFlag && !*decryptFlag {
        err := EncryptFile(password, flag.Arg(0), flag.Arg(1))
        if err != nil {
            panic(err.Error())
        }
    }

    elapsed := time.Since(start)
    fmt.Printf("Took %s\n", elapsed)
}
