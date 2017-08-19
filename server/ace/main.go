package main

import (
	"encoding/hex"
	"crypto/rand"
    "crypto/x509"
    "crypto/tls"
    "io/ioutil"
    "net/http"
    "encoding/json"
    "log"
)

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
    // Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}
	
func doAuth(username, password string) bool {
	if username == "user" && password == "mypassword123"{
		return true
	} else {
		return false
	}
}

type AuthResponse struct{
    EncryptionKey string
}

type handler struct{}

//Handle HTTP requests (Client Auth already happened)
func (h *handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	//Get Username from CN in Client Certificate
	username := req.TLS.PeerCertificates[0].Subject.CommonName
	//Get Password from POST data
	req.ParseForm()
	password := req.Form.Get("password")
	//INSECURE LOGGING
	log.Println("Username:",username,"Password:",password)
	//Validate Username and Password
	if doAuth(username,password){
		/*
		Auth is OK
		Generate Encryption key
		*/
		encryption_key, err := GenerateRandomBytes(32)
		if err != nil{
			log.Println("Error generating encryption key.")
			//Respond with HTTP 500
			http.Error(w, "{\"error\":\"Failed generating encryption key.\"}", http.StatusInternalServerError)
		} 
		jData, err := json.Marshal(AuthResponse{hex.EncodeToString(encryption_key)})
		if err != nil {
			http.Error(w, "{\"error\":\"Faild generating JSON object.\"}", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(jData)
			
		//json.NewEncoder(w).Encode(AuthResponse{EncryptionKey: hex.EncodeToString(encryption_key)})
	} else {
		http.Error(w, "{\"error\":\"Invalid credentials.\"}", 403)
	}
}

func main() {
	log.Println("ACE server started ... ")
	// ROot CA certificate
	caCert, err := ioutil.ReadFile("client.crt")
	if err != nil {
		log.Fatal(err)
	}
	//Load the Root CA
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	//TLS configuration for Client Certificate
	cfg := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caCertPool,
	}
	//TLS configuration for handler
	srv := &http.Server{
		Addr:      ":443",
		Handler:   &handler{},
		TLSConfig: cfg,
	}
	//Start TLS server
    log.Fatal(srv.ListenAndServeTLS("server.crt", "server.key"))
}