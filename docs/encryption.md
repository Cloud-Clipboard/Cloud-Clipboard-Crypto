# File Download and Upload

The Cloud Clipboard generates a content-encryption key (CEK) for each file that is uploaded. This CEK is used to encrypt the actual file content. The CEK is then encrypted together with other file metadata with a single wratched metadata-encryption key (MEK). The MEK is derived from the keyphrase and is used to encrypt the metadata for the file.

When a file is uploaded, the metadata is encrypted with the MEK and stored in the database. The actual file content is encrypted with the CEK and stored in a storage service.

When a file is downloaded, the metadata is decrypted with the MEK and the file content is then decrypted with the CEK from the decrypted metadata.

## Key Ratcheting

To make sure that not every metadata is encrypted with the bare keyphrase, a derived ratcheted key is used (MEK). This ensures, that if the MEK for any given metadata is compromised, only the following metadata is compromised and not the previous ones.

In the key ratcheting approach the keyphrase is passed through a key derivation function (KDF) for each metadata entry (N) to generate the MEK.

To improve performance, only the first pass through the KDF is done with a high configuration. Any subsequent passes are done with a lower configuration, which is sufficient to derive the key for the next metadata entry.

```mermaid
flowchart LR
    clipboardKey[Keyphrase]
    N@{ shape: circle, label: "N" }
    kdf[Key Derivation Function]
    metadataKey["Metadata Encryption Key (MEK)"]
    
    clipboardKey --> kdf -.- N -.-> kdf --> metadataKey
```

### CRUD Operations

The following sections describe the CRUD operations for file management in the Cloud Clipboard, including uploading, retrieving, downloading, deleting, and updating file metadata. The sequence diagrams illustrate the interactions between the client, server, database, and storage components.

## Uploading Content

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant Database
    participant Storage

    Client ->> Client: Generate content-encryption key (CEK)
    Client ->> Client: Encrypt content with content-encryption key (CEK)
    Client ->> Client: Derive metadata-encryption key (MEK) from keyphrase
    Client ->> Client: Encrypt metadata with metadata-encryption key (MEK)
    Client ->> Server: POST /files <br/> {token: JWT, <br/>metadata: encryptedMetadata, <br/>file: encryptedContent}
    Server ->> Server: Verify JWT
    alt JWT is valid
        Server ->> Server: Encrypt metadata with server-side metadata-specific key
        Server ->> Database: Store metadata
        Database -->> Server: Success
        Server ->> Server: Encrypt file with server-side content-specific key
        Server ->> Storage: Store file content
        Storage -->> Server: Success
        Server -->> Client: 200 OK <br/> {fileId: "...", metadata: encryptedMetadata}
    else JWT is invalid
        Server -->> Client: 401 Unauthorized <br/> {error: "Invalid JWT"}
    end
```

## Get Files Metadata

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant Database

    Client ->> Server: GET /files <br/> {token: JWT}
    Server ->> Server: Verify JWT
    alt JWT is valid
        Server ->> Database: Get metadata for dataspace
        Database -->> Server: File metadata
        Server ->> Server: Decrypt metadata with server-side metadata-specific key
        Server -->> Client: 200 OK <br/> {files: ["..."]}
    else JWT is invalid
        Server -->> Client: 401 Unauthorized <br/> {error: "Invalid JWT"}
    end
```

## Downloading Content

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant Database
    participant Storage

    Client ->> Server: GET /files/:fileId <br/> {token: JWT}
    Server ->> Server: Verify JWT
    alt JWT is valid
        Server ->> Database: Get metadata
        Database -->> Server: Metadata
        Server ->> Storage: Get file content
        Storage -->> Server: File content
        Server ->> Server: Decrypt metadata with server-side metadata-specific key
        Server ->> Server: Decrypt content with server-side content-specific key
        Server -->> Client: 200 OK <br/> {file: encryptedContent}
        Client ->> Client: Derive metadata-encryption key (MEK) from keyphrase
        Client ->> Client: Decrypt metadata with metadata-encryption key (MEK)
        Client ->> Client: Decrypt file with content-encryption key (CEK) from metadata
    else JWT is invalid
        Server -->> Client: 401 Unauthorized <br/> {error: "Invalid JWT"}
    end
```

## Deleting Content

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant Database
    participant Storage

    Client ->> Server: DELETE /files/:fileId <br/> {token: JWT}
    Server ->> Server: Verify JWT
    alt JWT is valid
        Server ->> Database: Delete metadata
        Database -->> Server: Success
        Server ->> Storage: Delete file content
        Storage -->> Server: Success
        Server -->> Client: 200 OK
    else JWT is invalid
        Server -->> Client: 401 Unauthorized <br/> {error: "Invalid JWT"}
    end
```

## Update Metadata

Updating the metadata of a file is required for example when the user wants to rename a file, add additional metadata or change their keyphrase.

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant Database

    Client ->> Server: PUT /files/:fileId/metadata <br/> {token: JWT, metadata: updatedEncryptedMetadata}
    Server ->> Server: Verify JWT
    alt JWT is valid
        Server ->> Server: Encrypt metadata with server-side metadata-specific key
        Server ->> Database: Update metadata
        Database -->> Server: Success
        Server -->> Client: 200 OK
    else JWT is invalid
        Server -->> Client: 401 Unauthorized <br/> {error: "Invalid JWT"}
    end
```
