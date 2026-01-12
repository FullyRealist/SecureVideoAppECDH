# SecureStream: Hybrid Video Encryption System

**SecureStream** is a prototype software complex for secure streaming multimedia data transmission. The project is developed on the **.NET 8** platform (Windows Forms) using a modern hybrid cryptosystem combining **ChaCha20-Poly1305** and **X25519**.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)
![Framework](https://img.shields.io/badge/.NET-8.0-purple.svg)

> The project was developed as part of a master's thesis on the protection of multimedia data in corporate networks.

## 📋 Key Features

* **Hybrid Encryption**: Combines the speed of a stream cipher with the reliability of asymmetric cryptography.
* **Perfect Forward Secrecy**: Uses ephemeral (one-time) keys. Compromise of a long-term key does not allow decryption of data from past sessions.
* **Data Authentication (AEAD)**: Usage of Poly1305 guarantees data integrity. Any attempt to modify the file (even by 1 byte) results in a decryption error.
* **Entropy Visualization**: A unique module for real-time visual analysis of encryption quality ("white noise" effect).
* **High Performance**:
    * Uses the **TAP** (Task-based Asynchronous Pattern) to ensure UI responsiveness.
    * Optimized memory management using `Span<byte>` to reduce Garbage Collector load.

## 🛠 Tech Stack

* **Language**: C#
* **Framework**: .NET 8, Windows Forms.
* **Cryptography**: [Bouncy Castle](https://www.bouncycastle.org/) (algorithm implementation).
* **IDE**: Visual Studio 2022.

## 🔐 Cryptographic Architecture

The system uses the following primitives:

1.  **Key Agreement**:
    * Protocol: **ECDH** on **Curve25519 (X25519)**.
    * Provides a 128-bit security level with a 32-byte key.
2.  **Encryption**:
    * Algorithm: **ChaCha20** (stream cipher).
    * Speed: 1.20–2.40 cpb (with AVX2 instructions).
3.  **Key Derivation Function (KDF)**:
    * Algorithm: **SHA-256** for hashing the shared secret.

### Secure Container Structure (.enc)

Each encrypted file has a header for autonomous decryption by the recipient:

| Field | Size | Description |
| :--- | :--- | :--- |
| **Length** | 4 bytes | Length of the public key |
| **Ephemeral PubKey** | 32 bytes | Sender's one-time public key (X25519) |
| **Nonce** | 12 bytes | Unique salt to protect against replay attacks |
| **Payload + Tag** | Variable | Encrypted data + 16 bytes Poly1305 tag |

## 🚀 Installation and Setup

1.  **Clone the repository**:
    ```bash
    git clone [https://github.com/FullyRealist/SecureVideoAppECDH.git](https://github.com/FullyRealist/SecureVideoAppECDH.git)
    ```
2.  **Open the project**:
    Launch the `.sln` solution file in Visual Studio 2022.
3.  **Dependencies**:
    Ensure the `BouncyCastle.Cryptography` package is installed via NuGet.
4.  **Run**:
    Compile and run the project (F5). On the first run, the application will automatically generate a user key pair in the `keys_ecdh.conf` file.

## 🖥 Usage

1.  Click **"Select File"** (Обрати файл) and choose a video file.
2.  Click **"Encrypt"** (Зашифрувати).
    * The program will generate a unique ephemeral key.
    * The visualization window will show "white noise," demonstrating high ciphertext entropy.
3.  To view, select the `.enc` file and click **"Decrypt"** (Розшифрувати).
    * The video will play only if the Poly1305 integrity check is successful.

## ⚠️ Disclaimer

This project is a research prototype. Although industry-standard algorithms (RFC 7539, RFC 7748) are used, the software implementation has not undergone a professional security audit.

---
© 2025. Odesa National Maritime University.
