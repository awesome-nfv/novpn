package main

import (
	"encoding/hex"
	"crypto/rand"
    "crypto/x509"
    "crypto/tls"
    "io/ioutil"
    "net/http"
    "encoding/json"
    "database/sql"
    "log"
    "flag"
    "os"

    _ "github.com/go-sql-driver/mysql"
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
	if username == "myusername" && password == "mypassword123"{
		return true
	} else {
		return false
	}
}

func storeEncryptionKey(username string, key []byte) (string, error) {
	db, err := sql.Open("mysql", "root:secretpassword@tcp(127.0.0.1:3306)/novpn")
	if err != nil {
		log.Println("Error generating database connection:",err)
		return "", err
	}
	defer db.Close()
	
	user_id, err := GenerateRandomBytes(32)
	if err != nil {
		log.Println("Error generating user-id:",err)
		return "", err
	}
	
	user_id_hex := hex.EncodeToString(user_id)
	stmtIns, err := db.Prepare("INSERT INTO session(`username`,`user-id`,`encryption-key`) VALUES(?,?,?);")
	if err != nil {
		log.Println("Error preparing statement:",err)
		return "", err
	}
	defer stmtIns.Close()
	_, err = stmtIns.Exec(username,user_id_hex,key)
	if err != nil {
		log.Println("Could not insert encryption key to Database:",err)
		return "", err
	}
	return user_id_hex, nil
}

func getGatewaysInfo() (map[string]*Gateway,error){
	gateways := make(map[string]*Gateway)

	return gateways,nil
}

type Gateway struct {
	GatewayIP string
	Routes []string
}

type AuthResponse struct{
    EncryptionKey string
    UserID string
    
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
		log.Println("User",username,"successfully authenticated.")
		encryption_key, err := GenerateRandomBytes(32)
		if err != nil{
			log.Println("Error generating encryption key.")
			http.Error(w, "{\"error\":\"Unknown server erros.\"}", http.StatusInternalServerError)
		}
		//Write data to session key Database
		user_id, err := storeEncryptionKey(username,encryption_key)
		if nil != err {
			log.Println("Error storing key:",err)
			http.Error(w, "{\"error\":\"Unknown server error.\"}", http.StatusInternalServerError)
		}
		jData, err := json.Marshal(AuthResponse{hex.EncodeToString(encryption_key),user_id})
		if err != nil {
			log.Println("Faild generating JSON object.")
			http.Error(w, "{\"error\":\"Unknown server error.\"}", http.StatusInternalServerError)
		}
		log.Println("Username:",username)
		log.Println("User ID:",user_id)
		log.Println("Encryption Key:",encryption_key)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write(jData)
	} else {
		log.Println("User",username,"sent invalid credentials.")
		http.Error(w, "{\"error\":\"Invalid credentials.\"}", 403)
	}
}

func main() {
	log.Println("ACE server started ... ")
	//Get gateways info
	gateways, err := getGatewaysInfo()
	if nil != err {
		log.Println("Error getting Gateway information:",err)
	}
	log.Println(gateways)
	os.Exit(0)
	server_cert := flag.String("cert","client.crt","server certificate (.crt)")
	server_key := flag.String("key","client.key","server certificate key (.key)")
	ca_cert := flag.String("ca","ca.crt","CA certificate (.crt)")
	flag.Parse()
	//Load CA
	caCert, err := ioutil.ReadFile(*ca_cert)
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
    log.Fatal(srv.ListenAndServeTLS(*server_cert,*server_key))
}