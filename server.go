package main

import (
    "bytes"
    "context"
    "crypto/md5"
    "database/sql"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "github.com/afocus/captcha"
    _ "github.com/go-sql-driver/mysql"
    "github.com/gorilla/mux"
    "github.com/gorilla/securecookie"
    "github.com/gorilla/sessions"
    "golang.org/x/crypto/scrypt"
    "html/template"
    "image/color"
    "image/png"
    "io"
    "math/rand"
    "net/http"
    "os"
    "regexp"
    "strconv"
    "strings"
    "time"
)

var store *sessions.CookieStore

var cap *captcha.Captcha


func init() {
    store = sessions.NewCookieStore(securecookie.GenerateRandomKey(64), securecookie.GenerateRandomKey(32))
    store.Options = &sessions.Options {
        MaxAge: 60 * 60 * 2, // 2 hours
        HttpOnly: true,
    }
}

func init() {
    cap = captcha.New()
    err := cap.SetFont("comic.ttf")  // upload to server
    if err != nil {
        panic(err.Error())
    }
    cap.SetSize(128, 64)
    cap.SetDisturbance(captcha.NORMAL)  // NORMAL || MEDIUM || HIGH
    cap.SetFrontColor(color.RGBA{255, 255, 255, 255})
    cap.SetBkgColor(color.RGBA{255, 0, 0, 255}, color.RGBA{0, 0, 255, 255}, color.RGBA{0, 153, 0, 255})
}

func upload(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "session")

    auth, ok := session.Values["authenticated"].(bool)
    if !ok || !auth {
        http.Error(w, fmt.Sprintf("%d %s", http.StatusForbidden, http.StatusText(http.StatusForbidden)), http.StatusForbidden)
        return
    }

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

        var keyType string
        action := r.FormValue("action")
        if action == "enc" {
            keyType = "public_key"
        } else if action == "dec" {
            keyType = "private_key"
        }

        ctx := context.Background()
        db, err := sql.Open("mysql", "root:root@/upb")

        if err != nil {
            fmt.Println(err)
        }

        name := session.Values["username"]

        rows, err := db.QueryContext(ctx, "SELECT " + keyType + " FROM users WHERE name = ?", name)
        if err != nil {
            fmt.Println(err)
        }

        defer rows.Close()

        var keyStr string
        for rows.Next() {
            if err := rows.Scan(&keyStr); err != nil {
                fmt.Println(err)
            }
        }

        key := []byte(keyStr)

        if action == "enc" {
            // TODO - add ".enc" extension to encrypted file
            startTime := time.Now()

            err = EncryptFile(key, in_path, out_path)
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

                err = DecryptFile(key, in_path, out_path)
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
	userCap := request.FormValue("captcha")
    redirectTarget := "/"

    session, _ := store.Get(request, "session")

    if userCap != session.Values["captchaStr"] {
        session.Values["captchaCorrect"] = false
        session.Save(request, response)
        http.Redirect(response, request, redirectTarget, 302)
    } else {
        session.Values["captchaCorrect"] = true
    }

    
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
        session.Values["username"] = name
        session.Values["authenticated"] = true
        session.Values["pswdCorrect"] = true
        fmt.Println("same")
    } else {
        session.Values["username"] = ""
        session.Values["authenticated"] = false
        session.Values["pswdCorrect"] = false
    }

    session.Save(request, response)
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
    fmt.Println("reghandler")

    session, _ := store.Get(request, "session")

	name := request.FormValue("name")
	pass := request.FormValue("password")
    passConf := request.FormValue("passwordconf")
    userCap := request.FormValue("captcha")
    fmt.Println("Registration")
    fmt.Println("Name: ")
    fmt.Println(name)
    fmt.Println("Password: ")
    fmt.Println(pass)
    fmt.Println("PasswordConf: ")
    fmt.Println(passConf)
    fmt.Println("User Captcha: ")
    fmt.Println(userCap)

    var redir = "/registerPage"

    //check if passwords match
    //check if name is size of <5, 20>
    //check if name only containt letters + numbers
    //password should be 10 chars or longer
    //pass should have at least one lowercase one uppercase one digit and one special character
    //pass should NOT contain words admin and root
    //check if captcha is correct

    isAlphaNum := regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString
   
    fmt.Println(len(pass) >= 10)
    fmt.Println(isAlphaNum(name))
    fmt.Println((len(name) >= 5 && len(name) <= 20))
    fmt.Println(pass == passConf)

    var capOk bool
    if userCap != session.Values["captchaStr"] {
        capOk = false
        session.Values["captchaCorrect"] = false
    } else {
        capOk = true
        session.Values["captchaCorrect"] = true
    }

    var nameOk bool
    if isAlphaNum(name) &&
        (len(name) >= 5 && len(name) <= 20) &&
        !strings.Contains(name, "admin") &&
        !strings.Contains(name, "root") {
            nameOk = true
            session.Values["nameCorrect"] = true
    } else {
        nameOk = false
        session.Values["nameCorrect"] = false
    }

    var pswdOk bool
    if len(pass) >= 10 &&
        pass == passConf &&
        strings.ContainsAny(pass, "0123456789") &&
        strings.ContainsAny(pass, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") &&
        strings.ContainsAny(pass, "abcdefghijklmnopqrstuvwxyz") &&
        strings.ContainsAny(pass, "!@#$%^&*()/-+.,") {
            pswdOk = true
            session.Values["pswdCorrect"] = true
    } else {
        pswdOk = false
        session.Values["pswdCorrect"] = false
    }

    if capOk && nameOk && pswdOk {
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

        var nameExists bool
        var nameFromDB string
        rows, err := db.QueryContext(ctx, "SELECT name FROM users WHERE name = ?", name)
        if err != nil {
            fmt.Println(err)
        }
        defer rows.Close()
        for rows.Next() {
            if err := rows.Scan(&nameFromDB); err != nil {
                fmt.Println(err)
            }
        }
        if nameFromDB == "" {
            nameExists = false
            session.Values["nameExists"] = false
        } else {
            nameExists = true
            session.Values["nameExists"] = true
        }

        if nameExists == false {
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
    }
    session.Save(request, response)
	http.Redirect(response, request, redir, 302)
}

func logoutHandler(response http.ResponseWriter, request *http.Request) {
    session, _ := store.Get(request, "session")
    session.Values["username"] = ""
    session.Values["authenticated"] = false
    session.Options.MaxAge = -1
    session.Save(request, response)
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
<form method="post" action="/logout">
    <button type="submit">Logout</button>
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
    <font color="red">{{.pswdErr}}</font>
</br></br>
    <img src="data:image/png;base64,{{.img}}">
</br></br>
    <label for="captcha">Enter the text you see in the image above</label>
    <input type="text" id="captcha", name="captcha">
    <font color="red">{{.capErr}}</font>
</br></br>
    <button type="submit">Login</button>
</form>

If you are not registered yet, click 
<form method="post" action="/registerPage">
    <button type="submit">here</button>
</form>
to register..`

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
    <font color="red">{{.nameErr}}</font>
 </br></br>
    <label for="password">Password</label>
    <input type="password" id="password" name="password">
    <font color="red">{{.pswdErr}}</font>
</br></br>
    <label for="passwordconf">Confirm password</label>
    <input type="password" id="passwordconf" name="passwordconf">
</br></br>
    <img src="data:image/png;base64,{{.img}}">
</br></br>
    <label for="captcha">Enter the text you see in the image above</label>
    <input type="text" id="captcha", name="captcha">
    <font color="red">{{.capErr}}</font>
</br></br>
    <button type="submit">Register</button>
</form>`

func genCaptcha() (string, string) {
    img, str := cap.Create(2, captcha.NUM) // increse captcha length, characters: NUM || LOWER || UPPER || ALL
    fmt.Println("Captcha str:")
    fmt.Println(str)
    var buff bytes.Buffer
    png.Encode(&buff, img)
    return base64.StdEncoding.EncodeToString(buff.Bytes()), str
}

func registerPageHandler(response http.ResponseWriter, request *http.Request) {
    tmpl := template.Must(template.New("registerTmpl").Parse(registerPage))
    captchaImg, capStr := genCaptcha()

    session, _ := store.Get(request, "session")
    session.Values["captchaStr"] = capStr

    var exists bool
    _, exists = session.Values["nameCorrect"]
    if exists == false {
        session.Values["nameCorrect"] = true
    }
    _, exists = session.Values["nameExists"]
    if exists == false {
        session.Values["nameExists"] = false
    }
    _, exists = session.Values["pswdCorrect"]
    if exists == false {
        session.Values["pswdCorrect"] = true
    }
    _, exists = session.Values["captchaCorrect"]
    if exists == false {
        session.Values["captchaCorrect"] = true
    }

    varmap := map[string]interface{}{
        "nameErr" : "",
        "pswdErr" : "",
        "img" : captchaImg,
        "capErr" : "",
    }

    if session.Values["nameCorrect"] == false {
        varmap["nameErr"] = `Username does not satisfy requirements`
    }
    if session.Values["nameExists"] == true {
        varmap["nameErr"] = `Username already exists!`
    }
    if session.Values["pswdCorrect"] == false {
        varmap["pswdErr"] = `Wrong password`
    }
    if session.Values["captchaCorrect"] == false {
        varmap["capErr"] = `CAPTCHA error! Try again`
    }

    session.Save(request, response)
    tmpl.Execute(response, varmap)
	//fmt.Fprintf(response, registerPage)
}

func indexPageHandler(response http.ResponseWriter, request *http.Request) {
    tmpl := template.Must(template.New("indexTmpl").Parse(indexPage))
    captchaImg, capStr := genCaptcha()

    session, _ := store.Get(request, "session")
    session.Values["captchaStr"] = capStr

    var exists bool
    _, exists = session.Values["captchaCorrect"]
    if exists == false {
        session.Values["captchaCorrect"] = true
    }
    _, exists = session.Values["pswdCorrect"]
    if exists == false {
        session.Values["pswdCorrect"] = true
    }

    varmap := map[string]interface{}{
        "pswdErr" : "",
        "img": captchaImg,
        "capErr": "",
    }

    if session.Values["captchaCorrect"] == false {
        varmap["capErr"] = `CAPTCHA error! Try again`
    }
    if session.Values["pswdCorrect"] == false {
        varmap["pswdErr"] = `Wrong password`
    }

    session.Save(request, response)
    tmpl.Execute(response, varmap)
	//fmt.Fprintf(response, indexPage)
}

func keysPageHandler(response http.ResponseWriter, request *http.Request) {
    session, _ := store.Get(request, "session")
    auth, ok := session.Values["authenticated"].(bool)
    if !ok || !auth {
        http.Error(response, fmt.Sprintf("%d %s", http.StatusForbidden, http.StatusText(http.StatusForbidden)), http.StatusForbidden)
        return
    }
	fmt.Fprintf(response, keysPage)
}

func backHandler(response http.ResponseWriter, request *http.Request) {
    session, _ := store.Get(request, "session")
    auth, ok := session.Values["authenticated"].(bool)
    if !ok || !auth {
        http.Error(response, fmt.Sprintf("%d %s", http.StatusForbidden, http.StatusText(http.StatusForbidden)), http.StatusForbidden)
        return
    }
    http.Redirect(response, request, "/internal", 302)
}

func keysUploadHandler(response http.ResponseWriter, request *http.Request) {
    session, _ := store.Get(request, "session")
    auth, ok := session.Values["authenticated"].(bool)
    if !ok || !auth {
        http.Error(response, fmt.Sprintf("%d %s", http.StatusForbidden, http.StatusText(http.StatusForbidden)), http.StatusForbidden)
        return
    }
    name := session.Values["username"].(string)

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
            //res, err := db.ExecContext(ctx, "INSERT INTO users (public_key) VALUES (?)", publicKey)
            res, err := db.ExecContext(ctx, "UPDATE users SET public_key = ? WHERE name = ?", publicKey, name)
            fmt.Println("publicKey: " + publicKey)
            fmt.Println("name: " + name)

            if res != nil {
                fmt.Println(res)
            }
            if err != nil {
                fmt.Println(err)
            }
        }
        if privateKey != "" {
            //res, err := db.ExecContext(ctx, "INSERT INTO users (private_key) VALUES (?)", privateKey)
            res, err := db.ExecContext(ctx, "UPDATE users SET private_key = ? WHERE name = ?", privateKey, name)

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

func createDB() {
    ctx := context.Background()
    db, err := sql.Open("mysql", "root:root@/")
    if err != nil {
        fmt.Println(err)
    }
    _, err = db.ExecContext(ctx, "CREATE DATABASE IF NOT EXISTS upb;")
    if err != nil {
       fmt.Println(err)
    }
}

func createTable() {
    ctx := context.Background()
    db, err := sql.Open("mysql", "root:root@/upb")
    if err != nil {
        fmt.Println(err)
    }
    _, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS users(
        name VARCHAR(20),
        pass_hash VARCHAR(64),
        salt VARCHAR(22),
        public_key TEXT,
        private_key TEXT
    );`)
    if err != nil {
        fmt.Println(err)
    }
}

func main() {
    createDB()
    createTable()

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