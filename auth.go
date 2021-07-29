package go_auth

import (
	"bytes"
	"encoding/json"
	"net/http"
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
	CreatedAt string `json:"created_at"`
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
func Login(email, password string) (output AuthOutput) {
	if apiKey == nil || email == "" || password == "" {
		return
	}

	values := map[string]string{
		"api_key":  *apiKey,
		"email":    email,
		"password": password,
	}
	jsonData, err := json.Marshal(values)
	if err != nil {
		return
	}

	resp, err := http.Post(baseUrl+"v1/auth", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
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
		_ = json.NewDecoder(resp.Body).Decode(&output)
	}

	return
}

// ListUsers Lists all the users using machine access token
func ListUsers() (users []OutputUser) {
	users = make([]OutputUser, 0)

	if isValidMachineAccessToken() {
		client := &http.Client{}
		req, err := http.NewRequest("GET", baseUrl+"v1/user", nil)
		if err != nil {
			return
		}

		req.Header.Set("Access-Token", *userAccessToken)
		resp, err := client.Do(req)
		if err != nil {
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
			_ = json.NewDecoder(resp.Body).Decode(&users)
		}
	}
	return
}

// LoadUser Gets the users using machine access token
func LoadUser(userId string) (user OutputUser) {
	if isValidMachineAccessToken() {
		client := &http.Client{}
		req, err := http.NewRequest("GET", baseUrl+"v1/user/"+userId, nil)
		if err != nil {
			return
		}

		req.Header.Set("Access-Token", *userAccessToken)
		resp, err := client.Do(req)
		if err != nil {
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
			_ = json.NewDecoder(resp.Body).Decode(&user)
		}
	}
	return
}

// CreateUser Creates a new user using machine access token
func CreateUser(user User) bool {
	if isValidMachineAccessToken() {
		client := &http.Client{}
		jsonData, err := json.Marshal(user)
		if err != nil {
			return false
		}
		req, err := http.NewRequest("POST", baseUrl+"v1/user", bytes.NewBuffer(jsonData))
		if err != nil {
			return false
		}
		req.Header.Set("Access-Token", *userAccessToken)

		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return true
		}
	}
	return false
}

// UpdateUser Updates an existing user using user id and machine access token
func UpdateUser(userId string, user User) bool {
	if isValidMachineAccessToken() {
		client := &http.Client{}
		jsonData, err := json.Marshal(user)
		if err != nil {
			return false
		}
		req, err := http.NewRequest("PUT", baseUrl+"v1/user/"+userId, bytes.NewBuffer(jsonData))
		if err != nil {
			return false
		}
		req.Header.Set("Access-Token", *userAccessToken)

		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return true
		}
	}
	return false
}
