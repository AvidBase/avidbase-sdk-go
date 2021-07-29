package go_auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
)

var baseUrl string

var accountId *string
var apiKey *string

var machineAccessToken *string
var userAccessToken *string

type OutputUser struct {
	ID        string `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Status    int64  `json:"status"`
}

type AuthOutput struct {
	User        OutputUser      `json:"user"`
	Permissions map[string]bool `json:"permissions"`
}

type User struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
}

func Init(account, key string) {
	baseUrl = "https://dev-api.avidbase.com/"
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

// IsLoggedIn Returns whether the user is logged in or not
func IsLoggedIn() bool {
	return userAccessToken != nil && *userAccessToken != ""
}

// GetUserAccessToken Returns user access token if available after logging in
func GetUserAccessToken() string {
	if userAccessToken == nil {
		return ""
	}
	return *userAccessToken
}

// Login Authenticates the existing user using email and password
func Login(email, password string) (output AuthOutput, err error) {
	if accountId == nil || email == "" || password == "" {
		err = errors.New("account, email or password is missing")
		return
	}

	values := map[string]string{
		"account_uuid": *accountId,
		"email":        email,
		"password":     password,
	}
	jsonData, err := json.Marshal(values)
	if err != nil {
		err = errors.New("unable to json encode given api key, email and password")
		return
	}

	resp, err := http.Post(baseUrl+"v1/auth", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		err = errors.New("unable to make an auth call")
		return
	}
	defer resp.Body.Close()

	// Set the user access token if it exists
	if resp.Header.Get("Access-Token") != "" {
		accessToken := resp.Header.Get("Access-Token")
		userAccessToken = &accessToken
	}

	if resp.StatusCode == http.StatusOK {
		//Decode the data
		err = json.NewDecoder(resp.Body).Decode(&output)
		if err != nil {
			err = errors.New("unable to decode auth response")
			return
		}
	} else {
		err = errors.New("authentication failed, status code: " + strconv.Itoa(resp.StatusCode))
		return
	}

	return
}

// ListUsers Lists all the users using machine access token
func ListUsers() (users []OutputUser, err error) {
	users = make([]OutputUser, 0)

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
		err = errors.New("list users failed, status code: " + strconv.Itoa(resp.StatusCode))
		return
	}

	// Set the user access token if it exists
	if resp.Header.Get("Access-Token") != "" {
		accessToken := resp.Header.Get("Access-Token")
		userAccessToken = &accessToken
	}

	//Decode the data
	err = json.NewDecoder(resp.Body).Decode(&users)
	if err != nil {
		err = errors.New("unable to decode a list users response")
		return
	}

	return
}

// LoadUser Gets the users using machine access token
func LoadUser(userId string) (user OutputUser, err error) {
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
		err = errors.New("get user failed, status code: " + strconv.Itoa(resp.StatusCode))
		return
	}

	// Set the user access token if it exists
	if resp.Header.Get("Access-Token") != "" {
		accessToken := resp.Header.Get("Access-Token")
		userAccessToken = &accessToken
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
func CreateUser(user User) (err error) {
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
		err = errors.New("create user failed, status code: " + strconv.Itoa(resp.StatusCode))
		return
	}

	// Set the user access token if it exists
	if resp.Header.Get("Access-Token") != "" {
		accessToken := resp.Header.Get("Access-Token")
		userAccessToken = &accessToken
	}

	return
}

// UpdateUser Updates an existing user using user id and machine access token
func UpdateUser(userId string, user User) (err error) {
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
		err = errors.New("update user failed, status code: " + strconv.Itoa(resp.StatusCode))
		return
	}

	// Set the user access token if it exists
	if resp.Header.Get("Access-Token") != "" {
		accessToken := resp.Header.Get("Access-Token")
		userAccessToken = &accessToken
	}

	return
}
