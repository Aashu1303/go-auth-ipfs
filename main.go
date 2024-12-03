package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

var (
	pinataAPIKey    string
	pinataAPISecret string
	userHashes      = struct {
		sync.RWMutex
		m map[string]string
	}{m: make(map[string]string)}
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func initPinata() {
	pinataAPIKey = os.Getenv("PINATA_API_KEY")
	pinataAPISecret = os.Getenv("PINATA_API_SECRET")

	if pinataAPIKey == "" || pinataAPISecret == "" {
		log.Fatalf("Pinata API credentials are missing. Set PINATA_API_KEY and PINATA_API_SECRET environment variables.")
	}
}

func storeUserOnPinata(user User) (string, error) {
	// Serialize user data to JSON
	data, err := json.Marshal(user)
	if err != nil {
		return "", fmt.Errorf("failed to serialize user: %v", err)
	}

	// Create a new POST request to Pinata
	url := "https://api.pinata.cloud/pinning/pinFileToIPFS"
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add file or data to the multipart form (adjust according to your data type)
	part, err := writer.CreateFormFile("file", "user_data.json")
	if err != nil {
		return "", fmt.Errorf("failed to create form file: %v", err)
	}

	// Write the serialized user data into the form field
	_, err = part.Write(data)
	if err != nil {
		return "", fmt.Errorf("failed to write data to part: %v", err)
	}

	// Close the multipart writer
	err = writer.Close()
	if err != nil {
		return "", fmt.Errorf("failed to close writer: %v", err)
	}

	// Create the request
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	// Set the Authorization header with the Bearer JWT token
	req.Header.Set("Authorization", "Bearer "+os.Getenv("PINATA_JWT_TOKEN"))
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Execute the request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to upload to Pinata: %v", err)
	}
	defer resp.Body.Close()

	// Check if the upload was successful
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to upload: received status %s", resp.Status)
	}

	// Parse the response
	var respData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return "", fmt.Errorf("failed to decode Pinata response: %v", err)
	}

	// Extract the IPFS hash from the response
	hash, ok := respData["IpfsHash"].(string)
	if !ok {
		return "", fmt.Errorf("failed to extract IPFS hash from response")
	}

	return hash, nil
}

func retrieveUserFromPinata(hash string) (*User, error) {
	// Use a public Pinata gateway to retrieve the file
	url := fmt.Sprintf("https://gateway.pinata.cloud/ipfs/%s", hash)

	// Set a timeout for the request
	client := &http.Client{
		Timeout: 10 * time.Second, // Timeout of 10 seconds
	}

	// Make the HTTP GET request
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve data from Pinata: %v", err)
	}
	defer resp.Body.Close()

	// Check for non-OK HTTP status codes
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve data from Pinata: received status %s", resp.Status)
	}

	// Decode the JSON response into a User struct
	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to deserialize user data: %v", err)
	}
	return &user, nil
}

func signUpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Hash the password before storing
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Store the user with hashed password
	user.Password = string(hashedPassword)
	hash, err := storeUserOnPinata(user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Store the user's hash for login
	userHashes.Lock()
	userHashes.m[user.Username] = hash
	userHashes.Unlock()

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "User %s created successfully with Pinata IPFS hash: %s", user.Username, hash)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "Invalid request method"}`, http.StatusMethodNotAllowed)
		return
	}

	var req User
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid input"}`, http.StatusBadRequest)
		return
	}

	userHashes.RLock()
	hash, exists := userHashes.m[req.Username]
	userHashes.RUnlock()
	if !exists {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

	// Retrieve user data from Pinata
	user, err := retrieveUserFromPinata(hash)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	// Compare hashed password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil {
		http.Error(w, `{"error": "Invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	// Send welcome message on successful login
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": fmt.Sprintf("Welcome, %s!", req.Username),
	})
}

// You can set up an HTTP server to test this handler function.
func main() {
	if err := godotenv.Load(); err != nil {
		log.Printf("No .env file found. Proceeding with existing environment variables.")
	}

	initPinata()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	http.HandleFunc("/signup", signUpHandler)
	http.HandleFunc("/login", loginHandler)

	fmt.Printf("Server running on http://0.0.0.0:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
