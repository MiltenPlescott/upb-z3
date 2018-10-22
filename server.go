package main

import (
    "fmt"
    "net/http"
    "html/template"
    "io"
    "os"
    "crypto/md5"
    "time"
    "strconv"
    "strings"
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

        password := r.FormValue("password")
        action := r.FormValue("action")
    
        if action == "enc" {
            // TODO - add ".enc" extension to encrypted file
            startTime := time.Now()
            err = EncryptFile([]byte(password), in_path, out_path)
            elapsedTime := time.Since(startTime)
            if err != nil {
                fmt.Println(err)
                return
            }
            
            fmt.Println("Encryption took %i ms", elapsedTime)

            // TODONE - download encrypted file as <filename>.enc
            w.Header().Add("Content-Disposition", "Attachment; filename=\"" + handler.Filename + ".enc\"")
            http.ServeFile(w, r, out_path)

            os.Remove(in_path)
            os.Remove(out_path)
        }else if action == "dec" {
            // TODONE - only accept files with ".enc" extension
            if strings.HasSuffix(handler.Filename, ".enc") {
                startTime := time.Now()
                err = DecryptFile([]byte(password), in_path, out_path)
                elapsedTime := time.Since(startTime)
                if err != nil {
                    fmt.Println(err)
                    return
                }
                fmt.Println("Decryption took %i ms", elapsedTime)
                // TODONE - download decrypted file as <filename> (without .enc)
                w.Header().Add("Content-Disposition", "Attachment; filename=\"" + strings.TrimSuffix(handler.Filename, ".enc") + "\"")
                http.ServeFile(w, r, out_path)

                os.Remove(in_path)
                os.Remove(out_path)
            }
        }
    }
}

func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "Hello, you requested: %s\n", r.URL.Path)
    })
    http.HandleFunc("/upload", upload)

    out_files := http.FileServer(http.Dir("./out_files/"))
    http.Handle("/files/", http.StripPrefix("/files/", out_files))

    http.ListenAndServe(":80", nil)
}
