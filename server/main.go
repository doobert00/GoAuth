package main

import (
	"context"
	"crypto/md5"
	"io"
	"log"
	"net/http"
	"regexp"

	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var MIN_PW_LEN string = "1"
var MAX_PW_LEN string = "25"
var PW_REGEX string = "^[a-zA-Z0-9-#:&]{" + MIN_PW_LEN + "," + MAX_PW_LEN + "}$"

var MONGO_URI string = "mongodb://localhost:27017"
var DATABASE string = "test"
var CRED_COLL string = "credentials"
var TOKEN_COLL string = "tokens"

type credential_record struct {
	User string `json:"user,omitempty" bson:"user,omitempty"`
	Pass string `json:"pass,omitempty" bson:"pass,omitempty"`
}

type token_record struct {
	User  string `json:"user,omitempty" bson:"user,omitempty"`
	Token string `json:"token,omitempty" bson:"token,omitempty"`
}

func main() {
	router := gin.Default()
	router.Use(cors.Default())

	router.GET("/", ping)
	router.POST("/auth", postAuth)
	router.POST("/signup", postSignUp)
	router.POST("/signout", postSignOut)
	http.ListenAndServeTLS(":443", "server.crt", "server.key", router)
}

func ping(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, "Pung")
}

func postSignUp(c *gin.Context) {
	bodyAsBytesArr, _ := io.ReadAll(c.Request.Body)
	requestBody := make(map[string]interface{})
	json.Unmarshal(bodyAsBytesArr, &requestBody)
	user := requestBody["user"].(string)
	pass := requestBody["pass"].(string)

	r, _ := regexp.Compile(PW_REGEX)
	match_user := r.MatchString(user)
	match_pass := r.MatchString(pass)
	if !match_user || !match_pass {
		c.IndentedJSON(http.StatusBadRequest, "Username or Password contains restricted characters or is too long")
		return
	}
	encrypt_user := encrypt(user)
	encrypt_pass := encrypt(pass)

	result := add_user(encrypt_user, encrypt_pass)
	if !result {
		c.IndentedJSON(http.StatusInternalServerError, "There was a problem with the database :(")
	} else {
		c.IndentedJSON(http.StatusOK, "OK")
	}
}

func postAuth(c *gin.Context) {
	//Parse bytes -> JSON -> vars
	bodyAsBytesArr, _ := io.ReadAll(c.Request.Body)
	requestBody := make(map[string]interface{})
	json.Unmarshal(bodyAsBytesArr, &requestBody)
	user := requestBody["user"].(string)
	pass := requestBody["pass"].(string)

	//Validate against regex
	r, _ := regexp.Compile(PW_REGEX)
	match_user := r.MatchString(user)
	match_pass := r.MatchString(pass)
	if !match_user || !match_pass {
		c.IndentedJSON(http.StatusBadRequest, "Username or Password contains restricted characters or is too long")
		return
	}

	encrypt_user := encrypt(user)
	encrypt_pass := encrypt(pass)

	result := find_user(encrypt_user, encrypt_pass)
	if !result {
		c.IndentedJSON(http.StatusForbidden, "Invalid Credentials :(")
		return
	}
	token := add_token(encrypt_user)
	c.IndentedJSON(http.StatusOK, token)
}

func postSignOut(c *gin.Context) {
	bodyAsBytesArr, _ := io.ReadAll(c.Request.Body)
	requestBody := make(map[string]interface{})
	json.Unmarshal(bodyAsBytesArr, &requestBody)
	user := requestBody["user"].(string)
	token := requestBody["token"].(string)

	r, _ := regexp.Compile(PW_REGEX)
	match_user := r.MatchString(user)
	if !match_user {
		c.IndentedJSON(http.StatusBadRequest, "Username contains restricted characters or is too long")
		return
	}
	encrypt_user := encrypt(user)

	revoke_token(encrypt_user, token)
	c.IndentedJSON(http.StatusOK, "OK")
}

// TODO: Encryption is just a hash right now... we're never decrypting so encryption
//
//	really just amounts to using a consistent hash value.
func encrypt(message string) string {
	//Convert to byte array from string
	messageBytes := []byte(message)

	//Convert from byte array to base64 string
	base64Str := base64.StdEncoding.EncodeToString(messageBytes)
	return base64Str
}

func find_user(user string, pass string) bool {
	return_val := true
	//Connect
	clientOptions := options.Client().ApplyURI(MONGO_URI)
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Print(err)
		return_val = false
	}
	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Print(err)
		return_val = false
	}

	//Find record
	collection := client.Database(DATABASE).Collection(CRED_COLL)
	filter := credential_record{User: user, Pass: pass}
	var result credential_record
	err = collection.FindOne(context.Background(), filter).Decode(&result)
	if err != nil {
		log.Print(err)
		return_val = false
	}

	//Disconnect
	err = client.Disconnect(context.Background())
	if err != nil {
		log.Print(err)
		return_val = false
	}

	return return_val
}

func add_user(user string, pass string) bool {
	return_val := true
	//Connect
	clientOptions := options.Client().ApplyURI(MONGO_URI)
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Print(err)
		return_val = false
	}
	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Print(err)
		return_val = false
	}

	//Create and insert a record
	collection := client.Database(DATABASE).Collection(CRED_COLL)
	new_record := credential_record{User: user, Pass: pass}
	_, err = collection.InsertOne(context.Background(), new_record)
	if err != nil {
		log.Print(err)
		return_val = false
	}
	log.Print("Inserted record succesfully.")

	//Disconnect
	err = client.Disconnect(context.Background())
	if err != nil {
		log.Print(err)
		return_val = false
	}

	return return_val
}

func add_token(user string) string {
	return_val := ""
	//Connect
	clientOptions := options.Client().ApplyURI(MONGO_URI)
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Print(err)
	}
	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Print(err)
	}

	collection := client.Database(DATABASE).Collection(TOKEN_COLL)
	filter := token_record{User: user}
	var result token_record
	err = collection.FindOne(context.Background(), filter).Decode(&result)
	if err != nil {
		log.Print(err)
		//Create and insert a record
		token := GenerateToken(user)
		new_record := token_record{User: user, Token: token}
		_, err = collection.InsertOne(context.Background(), new_record)
		if err != nil {
			log.Print(err)
		} else {
			return_val = token
		}
		log.Print("Inserted record succesfully.")
	}

	//Disconnect
	err = client.Disconnect(context.Background())
	if err != nil {
		log.Print(err)
	}

	return return_val
}

func revoke_token(user string, token string) {
	clientOptions := options.Client().ApplyURI(MONGO_URI)
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Print(err)
	}
	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Print(err)
	}

	collection := client.Database(DATABASE).Collection(TOKEN_COLL)
	filter := token_record{User: user, Token: token}
	_, err = collection.DeleteOne(context.Background(), filter)
	if err != nil {
		log.Print(err)
	}
	log.Print("Deleted record succesfully.")

	//Disconnect
	err = client.Disconnect(context.Background())
	if err != nil {
		log.Print(err)
	}
}

func GenerateToken(user string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(user), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	hasher := md5.New()
	hasher.Write(hash)
	return hex.EncodeToString(hasher.Sum(nil))
}
