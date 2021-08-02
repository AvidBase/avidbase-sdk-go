package avidbase

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/mail"
	"strconv"
)

var baseUrl string

var accountId *string
var apiKey *string

var machineAccessToken *string

type AuthOutput struct {
	User        Identity        `json:"user"`
	Permissions map[string]bool `json:"permissions"`
}

type Identity struct {
	ID        string                 `json:"id"`
	FirstName string                 `json:"first_name"`
	LastName  string                 `json:"last_name"`
	Username  string                 `json:"username"`
	Email     string                 `json:"email"`
	Country   string                 `json:"country"`
	Data      map[string]interface{} `json:"data"`
}

type User struct {
	FirstName *string                `json:"first_name"`
	LastName  *string                `json:"last_name"`
	Username  *string                `json:"username"`
	Email     *string                `json:"email"`
	Password  *string                `json:"password"`
	Data      map[string]interface{} `json:"data"`
}

func Init(account, key string, isProduction bool) {
	if isProduction {
		baseUrl = "https://api.avidbase.com/"
	} else {
		baseUrl = "https://dev-api.avidbase.com/"
	}
	accountId = &account
	apiKey = &key
}

// isValidMachineAccessToken Validates whether the machine access token is available or not
// if not available generate a new machine access token
func isValidMachineAccessToken() bool {
	if machineAccessToken == nil {
		if !generateMachineAccessToken() {
			return false
		}
	}
	return true
}

// generateMachineAccessToken Generates a new machine access token using api key
func generateMachineAccessToken() bool {
	if accountId == nil || apiKey == nil {
		return false
	}
	values := map[string]string{"api_key": *apiKey}
	jsonData, err := json.Marshal(values)
	if err != nil {
		return false
	}

	resp, err := http.Post(baseUrl+"v1/account/"+*accountId+"/token", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK || resp.Header.Get("Access-Token") == "" {
		return false
	}

	accessToken := resp.Header.Get("Access-Token")
	machineAccessToken = &accessToken

	return true
}

// Login Authenticates the existing user using email/username and password
func Login(emailOrUsername, password string) (accessToken string, output AuthOutput, err error) {
	if accountId == nil || emailOrUsername == "" || password == "" {
		err = errors.New("account, email/username or password is missing")
		return
	}

	values := map[string]string{
		"account_uuid": *accountId,
		"password":     password,
	}
	_, err = mail.ParseAddress(emailOrUsername)
	if err != nil {
		values["username"] = emailOrUsername
	} else {
		values["email"] = emailOrUsername
	}

	jsonData, err := json.Marshal(values)
	if err != nil {
		err = errors.New("unable to json encode given api key, email/username and password")
		return
	}

	resp, err := http.Post(baseUrl+"v1/auth", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		err = errors.New("unable to make an auth call")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errorMessage, readErr := ioutil.ReadAll(resp.Body)
		if readErr != nil {
			err = errors.New("authentication failed, status code: " + strconv.Itoa(resp.StatusCode))
			return
		}
		err = errors.New(string(errorMessage) + ", status code: " + strconv.Itoa(resp.StatusCode))
		return
	}

	// Check if the access token is available or not
	if resp.Header.Get("Access-Token") == "" {
		err = errors.New("access token missing")
		return
	}

	//Decode the data
	err = json.NewDecoder(resp.Body).Decode(&output)
	if err != nil {
		err = errors.New("unable to decode auth response")
		return
	}

	// Set the user access token
	accessToken = resp.Header.Get("Access-Token")

	return
}

// ListUsers Lists all the users using machine access token
func ListUsers() (users []Identity, err error) {
	users = make([]Identity, 0)

	if !isValidMachineAccessToken() {
		err = errors.New("invalid api key or unable to generate machine access token")
		return
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", baseUrl+"v1/user", nil)
	if err != nil {
		err = errors.New("unable to create a list users request")
		return
	}

	req.Header.Set("Access-Token", *machineAccessToken)
	resp, err := client.Do(req)
	if err != nil {
		err = errors.New("unable to make a list users call")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errorMessage, readErr := ioutil.ReadAll(resp.Body)
		if readErr != nil {
			err = errors.New("list users failed, status code: " + strconv.Itoa(resp.StatusCode))
			return
		}
		err = errors.New(string(errorMessage) + ", status code: " + strconv.Itoa(resp.StatusCode))
		return
	}

	//Decode the data
	err = json.NewDecoder(resp.Body).Decode(&users)
	if err != nil {
		err = errors.New("unable to decode a list users response")
		return
	}

	return
}

// GetUser Get a user using user id and machine access token
func GetUser(userId string) (user Identity, err error) {
	if !isValidMachineAccessToken() {
		err = errors.New("invalid api key or unable to generate machine access token")
		return
	}

	client := &http.Client{}
	req, err := http.NewRequest("GET", baseUrl+"v1/user/"+userId, nil)
	if err != nil {
		err = errors.New("unable to create a get user request")
		return
	}

	req.Header.Set("Access-Token", *machineAccessToken)
	resp, err := client.Do(req)
	if err != nil {
		err = errors.New("unable to make a get user call")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errorMessage, readErr := ioutil.ReadAll(resp.Body)
		if readErr != nil {
			err = errors.New("get user failed, status code: " + strconv.Itoa(resp.StatusCode))
			return
		}
		err = errors.New(string(errorMessage) + ", status code: " + strconv.Itoa(resp.StatusCode))
		return
	}

	//Decode the data
	err = json.NewDecoder(resp.Body).Decode(&user)
	if err != nil {
		err = errors.New("unable to decode a get user response")
		return
	}

	return
}

// CreateUser Creates a new user using machine access token
func CreateUser(user User) (identity Identity, err error) {
	if !isValidMachineAccessToken() {
		err = errors.New("invalid api key or unable to generate machine access token")
		return
	}

	client := &http.Client{}
	jsonData, err := json.Marshal(user)
	if err != nil {
		err = errors.New("unable to json encode given user info")
		return
	}

	req, err := http.NewRequest("POST", baseUrl+"v1/user", bytes.NewBuffer(jsonData))
	if err != nil {
		err = errors.New("unable to create a create user request")
		return
	}
	req.Header.Set("Access-Token", *machineAccessToken)

	resp, err := client.Do(req)
	if err != nil {
		err = errors.New("unable to make a create user call")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errorMessage, readErr := ioutil.ReadAll(resp.Body)
		if readErr != nil {
			err = errors.New("create user failed, status code: " + strconv.Itoa(resp.StatusCode))
			return
		}
		err = errors.New(string(errorMessage) + ", status code: " + strconv.Itoa(resp.StatusCode))
		return
	}

	//Decode the data
	err = json.NewDecoder(resp.Body).Decode(&identity)
	if err != nil {
		err = errors.New("unable to decode a create user response")
		return
	}

	return
}

// UpdateUser Updates an existing user using user id and machine access token
func UpdateUser(userId string, user User) (identity Identity, err error) {
	if !isValidMachineAccessToken() {
		err = errors.New("invalid api key or unable to generate machine access token")
		return
	}

	client := &http.Client{}
	jsonData, err := json.Marshal(user)
	if err != nil {
		err = errors.New("unable to json encode given user info")
		return
	}

	req, err := http.NewRequest("PUT", baseUrl+"v1/user/"+userId, bytes.NewBuffer(jsonData))
	if err != nil {
		err = errors.New("unable to create an update user request")
		return
	}
	req.Header.Set("Access-Token", *machineAccessToken)

	resp, err := client.Do(req)
	if err != nil {
		err = errors.New("unable to make an update user call")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errorMessage, readErr := ioutil.ReadAll(resp.Body)
		if readErr != nil {
			err = errors.New("update user failed, status code: " + strconv.Itoa(resp.StatusCode))
			return
		}
		err = errors.New(string(errorMessage) + ", status code: " + strconv.Itoa(resp.StatusCode))
		return
	}

	//Decode the data
	err = json.NewDecoder(resp.Body).Decode(&identity)
	if err != nil {
		err = errors.New("unable to decode an update user response")
		return
	}

	return
}

// String returns a pointer to the string value passed in.
func String(v string) *string {
	return &v
}

// StringValue returns the value of the string pointer passed in or
// "" if the pointer is nil.
func StringValue(v *string) string {
	if v != nil {
		return *v
	}
	return ""
}
