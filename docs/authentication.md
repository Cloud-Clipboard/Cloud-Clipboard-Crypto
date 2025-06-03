# Cloud Clipboard Authentication Protocol

The Cloud Clipboard Authentication Protocol is designed to securely onboard users and authenticate them using a zero-knowledge proof mechanism. This document outlines the key steps involved in the authentication process, including key pair generation, onboarding, and authentication.

The protocol is based on a public-private keypair system, where the client derives a key pair from a user-provided keyphrase. The keyphase and the derived private key never leave the client, ensuring that the server does not have access to the user's keyphrase or private key. Instead, the server only stores the user's public key and verifies the user's identity through a challenge-response mechanism.

## Key Pair Generation

The client generates a key pair using a key derivation function (KDF) based on the user-provided keyphrase. From the derived private key, the client can compute the corresponding public key. This process ensures is deterministic, meaning that the same keyphrase will always produce the same key pair for the same dataspace.

```mermaid
flowchart LR
    A[Keyphrase] --> B[Key Deriviation Function]
    B --> C[Derived Private Key]
    C --> D[Derived Public Key] 
```

## Onboarding

The onboarding process is initiated when a user first interacts with the Cloud Clipboard service. In this step the client derives a key pair and sends the public key to the server. The server will from now on use this public key to verify the user's identity during authentication.

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant Database

    Client ->> Client: Derive key pair
    Client ->> Server: GET /auth/challenge
    Server ->> Database: Check if user is already onboarded
    Database -->> Server: Not yet onboarded
    Server -->> Client: 200 OK <br/> {onboarded: false}
    Client ->> Server: POST /auth/onboard <br/> {publicKey: "..."}
    Server ->> Database: Verify that user is not onboarded
    Database -->> Server: Not yet onboarded
    Server ->> Database: Store public key & onboarded state
    Database -->> Server: Success
    alt Onboarding Successful
        Server -->> Client: 200 OK <br/> {token: "JWT"}
    else Onboarding Failed
        Server -->> Client: 500 Internal Server Error <br/> {error: "Some Error"}
    end
```

## Authentication

Once the user is onboarded, they can authenticate themselves using their private key. The server challenges the client with a random challenge, which the client signs with their private key. The server then verifies the signature using the stored public key.

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant Database

    Client ->> Client: Derive key pair
    Client ->> Server: GET /auth/challenge
    Server ->> Database: Check if user is already onboarded
    Database -->> Server: User is onboarded
    Server ->> Server: Generate session challenge (e.g., "1234")
    Server -->> Client: 200 OK <br/> {challenge: "1234", onboarded: true}
    Client ->> Client: sign(challenge, privateKey)
    Client ->> Server: POST /auth/verify <br/> {signedChallenge: "..."}
    Server ->> Database: Get public key
    Database -->> Server: challenge: "1234", publicKey: "..."
    Server ->> Server: Verify signedChallenge (signature verification)
    alt Authentication Successful
        Server -->> Client: 200 OK <br/> {token: "JWT"}
    else Authentication Failed
        Server -->> Client: 401 Unauthorized <br/> {error: "Invalid Signature"}
    end
```