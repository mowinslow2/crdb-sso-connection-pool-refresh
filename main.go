package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cockroachdb/cockroach-go/v2/crdb/crdbpgx"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

var dbPool *pgxpool.Pool
var isTokenExpired = false

func insertRows(ctx context.Context, tx pgx.Tx, accts [4]uuid.UUID) error {
	// Insert four rows into the "accounts" table.
	if _, err := tx.Exec(ctx,
		"INSERT INTO accounts (id, balance) VALUES ($1, $2), ($3, $4), ($5, $6), ($7, $8)", accts[0], 250, accts[1], 100, accts[2], 500, accts[3], 300); err != nil {
		return err
	}
	return nil
}

func printBalances(conn *pgxpool.Pool) error {
	rows, err := conn.Query(context.Background(), "SELECT id, balance FROM accounts")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var balance int
		if err := rows.Scan(&id, &balance); err != nil {
			log.Fatal(err)
		}
		log.Printf("%s: %d\n", id, balance)
	}
	return nil
}

func transferFunds(ctx context.Context, tx pgx.Tx, from uuid.UUID, to uuid.UUID, amount int) error {
	// Read the balance.
	var fromBalance int
	if err := tx.QueryRow(ctx,
		"SELECT balance FROM accounts WHERE id = $1", from).Scan(&fromBalance); err != nil {
		return err
	}

	if fromBalance < amount {
		log.Println("insufficient funds")
	}

	// Perform the transfer.
	// log.Printf("Transferring funds from account with ID %s to account with ID %s...", from, to)
	if _, err := tx.Exec(ctx,
		"UPDATE accounts SET balance = balance - $1 WHERE id = $2", amount, from); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		"UPDATE accounts SET balance = balance + $1 WHERE id = $2", amount, to); err != nil {
		return err
	}
	return nil
}

func deleteRows(ctx context.Context, tx pgx.Tx, one uuid.UUID, two uuid.UUID) error {
	// Delete two rows into the "accounts" table.
	// log.Printf("Deleting rows with IDs %s and %s...", one, two)
	if _, err := tx.Exec(ctx,
		"DELETE FROM accounts WHERE id IN ($1, $2)", one, two); err != nil {
		return err
	}
	return nil
}

func executeWorkload() {
	// Insert initial rows
	var accounts [4]uuid.UUID
	for i := 0; i < len(accounts); i++ {
		accounts[i] = uuid.New()
	}

	err := crdbpgx.ExecuteTx(context.Background(), dbPool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		return insertRows(context.Background(), tx, accounts)
	})
	if err == nil {
		log.Println("New rows created.")
	} else {
		log.Fatal("error: ", err)
	}

	// Print out the balances
	//log.Println("Initial balances:")
	//printBalances(conn)

	// Run a transfer
	err = crdbpgx.ExecuteTx(context.Background(), dbPool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		return transferFunds(context.Background(), tx, accounts[2], accounts[1], 100)
	})
	if err == nil {
		log.Println("Transfer successful.")
	} else {
		log.Fatal("error: ", err)
	}

	// Print out the balances
	//log.Println("Balances after transfer:")
	//printBalances(conn)

	// Delete rows
	err = crdbpgx.ExecuteTx(context.Background(), dbPool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		return deleteRows(context.Background(), tx, accounts[0], accounts[1])
	})
	if err == nil {
		log.Println("Rows deleted.")
	} else {
		log.Fatal("error: ", err)
	}

	// Print out the balances
	//log.Println("Balances after deletion:")
	//printBalances(dbPool)
}

// Standard response format from Okta
type OktaResponse struct {
	RefreshToken string `json:"refresh_token"`
	IdToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`   // Not used in this demo
	ExpiresIn    int    `json:"expires_in"`   // Not used in this demo
	AccessToken  string `json:"access_token"` // Not used in this demo
	Scope        string `json:"scope"`        // Not used in this demo
}

/*
Returns new refresh_token and id_token

http --form POST https://${yourOktaDomain}/oauth2/default/v1/token \
accept:application/json \
authorization:'Basic MG9hYmg3M...' \
cache-control:no-cache \
content-type:application/x-www-form-urlencoded \
grant_type=refresh_token \
redirect_uri=http://localhost:8080 \
scope=offline_access%20openid \
refresh_token=MIOf-U1zQbyfa3MUfJHhvnUqIut9ClH0xjlDXGJAyqo
*/
func useRefreshToken(refreshToken string, oktaUrl string, clientID string, clientSecret string) (string, string) {
	form := url.Values{}
	form.Add("grant_type", "refresh_token")
	form.Add("scope", "openid offline_access")
	form.Add("refresh_token", refreshToken) // Use instead of username/password

	req, err := http.NewRequest("POST", oktaUrl, strings.NewReader(form.Encode()))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result OktaResponse
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return result.IdToken, result.RefreshToken
}

/*
Return id_token AND refresh_token to be used later

curl --location --request POST 'https://${yourOktaDomain}/oauth2/default/v1/token' \
-H 'Accept: application/json' \
-H 'Authorization: Basic ${Base64(${clientId}:${clientSecret})}' \
-H 'Content-Type: application/x-www-form-urlencoded' \
-d 'grant_type=password' \
-d 'redirect_uri=${redirectUri}' \
-d 'username=example@mailinator.com' \
-d 'password=a.gReAt.pasSword' \
-d 'scope=openid offline_access'
*/
func getTokens(oktaUrl string, clientID string, clientSecret string, oktaUsername string, oktaPassword string) OktaResponse {
	form := url.Values{}
	form.Add("grant_type", "password")
	form.Add("scope", "openid offline_access")
	form.Add("username", oktaUsername)
	form.Add("password", oktaPassword)

	req, err := http.NewRequest("POST", oktaUrl, strings.NewReader(form.Encode()))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result OktaResponse
	if err := json.Unmarshal(body, &result); err != nil { // Parse []byte to go struct pointer
		fmt.Println("Can not unmarshal JSON")
	}

	return result
}

func getConfig(response OktaResponse, oktaUrl string, clientID string, clientSecret string) (*pgxpool.Config, error) {
	// Create connection string with initial ID token
	// Update the next 3 variables in order to complete your DB connection string
	sqlUser := "sqlUser"
	host := "host"
	cert := "/ca.cert"
	dbURL := "postgresql://" + sqlUser + ":" + response.IdToken + "@" + host + ":26257/defaultdb?sslmode=verify-full&sslrootcert=" + cert + "&options=--crdb:jwt_auth_enabled=true"

	// Set initial connection pool configuration
	config, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		log.Fatal("error configuring the pool: ", err)
	}

	// Add additional configs
	config.MaxConns = 4
	config.MaxConnLifetime = (120 * time.Second)

	// BeforeConnect is called before a new connection is made. It is passed a copy of the underlying pgx.ConnConfig and
	// will not impact any existing open connections.
	config.BeforeConnect = func(ctx context.Context, config *pgx.ConnConfig) error {
		// check global variable
		if isTokenExpired {
			fmt.Println("ID Token is expired, issuing refresh")

			currentRefreshToken := os.Getenv("REFRESH_TOKEN")
			idToken, refreshToken := useRefreshToken(currentRefreshToken, oktaUrl, clientID, clientSecret)
			config.Password = idToken
			os.Setenv("REFRESH_TOKEN", refreshToken)
			isTokenExpired = false
		}

		return nil
	}

	return config, nil
}

func main() {
	// Env variables
	oktaUrl := os.Getenv("OKTA_URL")
	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	oktaUsername := os.Getenv("OKTA_USERNAME")
	oktaPassword := os.Getenv("PASSWORD")

	// Get initial ID token and refresh token using username/password
	resp := getTokens(oktaUrl, clientID, clientSecret, oktaUsername, oktaPassword)
	fmt.Println("Received initial ID Token")

	// Set env variable that tracks the refresh token to use
	os.Setenv("REFRESH_TOKEN", resp.RefreshToken)

	// Construct config for db pool
	config, err := getConfig(resp, oktaUrl, clientID, clientSecret)
	if err != nil {
		log.Fatal("error setting pgxpool config: ", err)
	}

	// Ensure token is not expired before acquiring a connection from the pool
	config.BeforeAcquire = func(ctx context.Context, c *pgx.Conn) bool {
		return !isTokenExpired
	}

	// Ensure token is not expired before releasing connection back to the pool
	config.AfterRelease = func(c *pgx.Conn) bool {
		return !isTokenExpired
	}

	// Create a connection pool to the database with all configs added
	dbPool, err = pgxpool.ConnectConfig(context.Background(), config)
	if err != nil {
		log.Fatal("error creating pool: ", err)
	}
	defer dbPool.Close()

	// Ticker will ensure we refresh our ID token every 30 seconds
	ticker := time.NewTicker(30 * time.Second)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				fmt.Println("Ticker set ID token to expired")
				isTokenExpired = true
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()

	// Workload runs every 6 seconds for ~1 minute
	// Every 30 seconds the token is set to 'expired' and a refresh is needed
	for i := 0; i < 10; i++ {
		executeWorkload()
		time.Sleep(6 * time.Second)
	}
}
