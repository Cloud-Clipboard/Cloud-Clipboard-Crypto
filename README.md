# Cloud Clipboard Crypto

This repository contains protocol documentation and source code for the client crypto component of the Cloud Clipboard frontend application.

By making this information open source, we aim to provide transparency and allow the community to contribute to the development of secure clipboard management solutions.

## Terminology

- **Dataspace**: A "dataspace" is a logical grouping of data that is encrypted and managed together. Each Cloud Clipboard has its own dataspace, which is identified by a unique identifier and is associated with a specific keyphrase.

- **Keyphrase**: The word "keyphrase" is used throughout the documentation. It describes the phrase that a user must provide to encrypt/decrypt their content and that is used to authenticate against the server for a given dataspace. The keyphrase never leaves the client and is specific to a dataspace.

## Protocol Documentation

The Cloud Clipboard aims to provide a end-to-end encrypted data transfer solution based on a zero-knowledge proof authentication protocol and symmetric encryption.

Please refer to the individual protocol documentations for detailed protocol specifications:

- [Authentication Protocol](docs/authentication.md)
- [Data Encryption Protocol](docs/encryption.md)
- [Challenge-Response Design Proposal*](docs/challenge-response-design.md)

\* not yet implemented, planned for future releases

## License

The repository is licensed under the [MIT License](LICENSE). This means you can use, modify, and distribute the code freely, as long as you include the original license in any copies or substantial portions of the software.

## Contributing

We welcome contributions to the Cloud Clipboard Crypto project! If you have ideas for improvements, bug fixes, or new features, please feel free to submit a pull request.
