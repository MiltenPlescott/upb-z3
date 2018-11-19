package main

import (
    "github.com/gorilla/mux"
	"fmt"
    "net/http"
    "regexp"
    "golang.org/x/crypto/scrypt"
    "math/rand"
    "encoding/hex" 
    "database/sql"
    _ "github.com/go-sql-driver/mysql"
    "context" 
    "bytes"
    "crypto/md5"
    "html/template"
    "io"
    "os"
    "strconv"
    "strings"
    "time"
)

func upload(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        crutime := time.Now().Unix()
        h := md5.New()
        io.WriteString(h, strconv.FormatInt(crutime, 10))
        token := fmt.Sprintf("%x", h.Sum(nil))

        t, _ := template.ParseFiles("web/upload.html")
        t.Execute(w, token)
    } else {
        // maximum size of file is 1 << 21 (2GB)
        r.ParseMultipartForm(1 << 21)
        file, handler, err := r.FormFile("uploadfile")

        if err != nil {
            fmt.Println(err)
            return
        }

        in_path := "./in_files/" + handler.Filename
        out_path := "./out_files/" + handler.Filename

        f, err := os.OpenFile(in_path, os.O_CREATE | os.O_WRONLY, 0600)
        if err != nil {
            fmt.Println(err)
            return
        }

        io.Copy(f, file)
        f.Close()
        file.Close()

        file, _, err = r.FormFile("uploadkey")

        if err != nil {
            fmt.Println(err)
            return
        }

        var key bytes.Buffer
        io.Copy(&key, file)

        action := r.FormValue("action")

        if action == "enc" {
            // TODO - add ".enc" extension to encrypted file
            startTime := time.Now()
            err = EncryptFile(key.Bytes(), in_path, out_path)
            elapsedTime := time.Since(startTime)
            if err != nil {
                fmt.Println(err)
                return
            }
            
            fmt.Println("Encryption took", elapsedTime)

            // TODONE - download encrypted file as <filename>.enc
            w.Header().Add("Content-Disposition", "Attachment; filename=\"" + handler.Filename + ".enc\"")
            http.ServeFile(w, r, out_path)

            os.Remove(in_path)
            os.Remove(out_path)
        } else if action == "dec" {
            // TODONE - only accept files with ".enc" extension
            if strings.HasSuffix(handler.Filename, ".enc") {
                startTime := time.Now()
                err = DecryptFile(key.Bytes(), in_path, out_path)
                elapsedTime := time.Since(startTime)
                if err != nil {
                    fmt.Println(err)
                    return
                }
                fmt.Println("Decryption took", elapsedTime)
                // TODONE - download decrypted file as <filename> (without .enc)
                w.Header().Add("Content-Disposition", "Attachment; filename=\"" + strings.TrimSuffix(handler.Filename, ".enc") + "\"")
                http.ServeFile(w, r, out_path)

                os.Remove(in_path)
                os.Remove(out_path)
            } 
        }
    }
}

func loginHandler(response http.ResponseWriter, request *http.Request) {
	name := request.FormValue("name")
	pass := request.FormValue("password")
    redirectTarget := "/"
    
    ctx := context.Background()
    db, err := sql.Open("mysql", "root:root@/upb")

    if err != nil {
        fmt.Println(err)
    }
    
    rows, err := db.QueryContext(ctx, "SELECT pass_hash, salt FROM users WHERE name = ?", name)
    if err != nil {
        fmt.Println(err)
    }

    defer rows.Close()

    var pass_hash string
    var salt string 

    for rows.Next() {
        if err := rows.Scan(&pass_hash, &salt); err != nil {
            fmt.Println(err)
        }
        fmt.Printf("%s is %s ,  %s\n", name, pass_hash, salt)
    }

    dk, err := scrypt.Key([]byte(pass), []byte(salt), 32768, 8, 1, 32)

    if err != nil {
        //TODO
    }

    hexDk := hex.EncodeToString(dk)
    fmt.Println(hexDk)
    if hexDk == pass_hash {
        redirectTarget = "/internal"
        fmt.Println("same")
    } 

	http.Redirect(response, request, redirectTarget, 302)
}

func generateSalt(length int) string {
    const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    b := make([]byte, length)
    for i := range b {
        b[i] = characters[rand.Intn(len(characters))]
    }
    return string(b)
}


func registerHandler(response http.ResponseWriter, request *http.Request) {
	name := request.FormValue("name")
	pass := request.FormValue("password")
    passConf := request.FormValue("passwordconf")
    fmt.Println("Registration")
    fmt.Println("Name: ")
    fmt.Println(name)
    fmt.Println("Password: ")
    fmt.Println(pass)
    fmt.Println("PasswordConf: ")
    fmt.Println(passConf)

    var redir = "/registerPage" 

    //check if passwords match
    //check if name is size of <5, 20>
    //check if name only containt letters + numbers
    //password should be 10 chars or longer
    //pass should have at least one lowercase one uppercase one digit and one special character
    //pass should NOT contain words admin and root

    isAlphaNum := regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString
   
    fmt.Println(len(pass) >= 10)
    fmt.Println(isAlphaNum(name))
    fmt.Println((len(name) >= 5 && len(name) <= 20))
    fmt.Println(pass == passConf)

    if len(pass) >= 10 &&
       isAlphaNum(name) &&
       (len(name) >= 5 && len(name) <= 20) &&
       pass == passConf &&
       strings.ContainsAny(pass, "0123456789") &&
       strings.ContainsAny(pass, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") &&
       strings.ContainsAny(pass, "abcdefghijklmnopqrstuvwxyz") &&
       strings.ContainsAny(pass, "!@#$%^&*()/-+.,") &&
       !strings.Contains(name, "admin") &&
       !strings.Contains(name, "root") {

        redir = "/"
    
        rand.Seed(time.Now().UnixNano())

        //22 chars for 128bit 
        salt := generateSalt(22)
        dk, err := scrypt.Key([]byte(pass), []byte(salt), 32768, 8, 1, 32)

        if err != nil {
            //TODO
        }

        hexDk := hex.EncodeToString(dk)

        fmt.Println("Salt: ")
        fmt.Println(salt)
        fmt.Println("Hash encoded: ")
        fmt.Println(hexDk)

        ctx := context.Background()
        db, err := sql.Open("mysql", "root:root@/upb")

        res, err := db.ExecContext(ctx,
            "INSERT INTO users (name, pass_hash , salt) VALUES (?, ?, ?)",
            name,
            hexDk,
            salt,
        )

        if res != nil {
            fmt.Println(res)
        }
        if err != nil {
            fmt.Println(err)
        }
    }
	http.Redirect(response, request, redir, 302)
}




func logoutHandler(response http.ResponseWriter, request *http.Request) {
	http.Redirect(response, request, "/", 302)
}

const keysPage = `<html>
<head>
    <title>File encryption/decryption</title>
</head>
<body>
    <form action="/keysupload" method="post">
Public Key: 
        <textarea rows="4" cols="50" id="pubk" name="pubk"></textarea> <br>
        Private Key: <textarea rows="4" cols="50" id="prik" name="prik"></textarea><br>
<br>
        <input type="submit" value="Upload"/> </br>
     </form>
<form method="get" action="/internal">
    <button type="submit">Back</button>
</form>
    
</body>
</html>`

const indexPage = 
`<h1>Login</h1>
<form method="post" action="/login">
    <label for="name">User name</label>
    <input type="text" id="name" name="name">
 </br></br>
    <label for="password">Password</label>
    <input type="password" id="password" name="password">
</br>
    <button type="submit">Login</button>
</form>

If you are not registered yet, click 
<form method="post" action="/registerPage">
    <button type="submit">here</button>
</form>
to register.`

const registerPage = 
`<h1>Register</h1>
Username can contain alphanumeric characters. Allowed username length is 5 to 20 characters
</br>
Usernames containing "admin" or "root" are not allowed
</br>
Password needs to contain at least one lowercase, one uppercase, one numeric and one special character and must be 10 chars or longer
<form method="post" action="/register">
    <label for="name">User name</label>
    <input type="text" id="name" name="name">
 </br></br>
    <label for="password">Password</label>
    <input type="password" id="password" name="password">
</br></br>
    <label for="passwordconf">Confirm password</label>
    <input type="password" id="passwordconf" name="passwordconf">
</br>
    <button type="submit">Register</button>
</form>`

func registerPageHandler(response http.ResponseWriter, request *http.Request) {
	fmt.Fprintf(response, registerPage)
}

func indexPageHandler(response http.ResponseWriter, request *http.Request) {
	fmt.Fprintf(response, indexPage)
}

func keysPageHandler(response http.ResponseWriter, request *http.Request) {
	fmt.Fprintf(response, keysPage)
}

func backHandler(response http.ResponseWriter, request *http.Request) {
	http.Redirect(response, request, "/internal", 302)
}

func keysUploadHandler(response http.ResponseWriter, request *http.Request) {
	publicKey := request.FormValue("pubk")
	privateKey := request.FormValue("prik")
    
    redir := "/keysPage" //if fails

    if publicKey != "" || privateKey != "" {
        redir = "/back"
        ctx := context.Background()
        db, err := sql.Open("mysql", "root:root@/upb")
        
        if err != nil {
            fmt.Println(err)
        }

        if publicKey != "" {
            res, err := db.ExecContext(ctx,
                "INSERT INTO users (public_key) VALUES (?)", publicKey)
            
            if res != nil {
                fmt.Println(res)
            }
            if err != nil {
                fmt.Println(err)
            }
        }
        if privateKey != "" {
            res, err := db.ExecContext(ctx,
                "INSERT INTO users (private_key) VALUES (?)", privateKey)

            if res != nil {
                fmt.Println(res)
            }
            if err != nil {
                fmt.Println(err)
            }
        }
    }

    http.Redirect(response, request, redir, 302)
}

func main() {
    
    var router = mux.NewRouter()
	router.HandleFunc("/", indexPageHandler)
	router.HandleFunc("/back", backHandler)
	router.HandleFunc("/internal", upload)
	router.HandleFunc("/registerPage", registerPageHandler)
	router.HandleFunc("/keysPage", keysPageHandler)

	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.HandleFunc("/logout", logoutHandler).Methods("POST")
    router.HandleFunc("/register", registerHandler).Methods("POST")
    router.HandleFunc("/keysupload", keysUploadHandler).Methods("POST")
    http.Handle("/", router)

    http.HandleFunc("/upload", upload)

    out_files := http.FileServer(http.Dir("./out_files/"))
    http.Handle("/files/", http.StripPrefix("/files/", out_files))

	http.ListenAndServe(":80", nil)
}