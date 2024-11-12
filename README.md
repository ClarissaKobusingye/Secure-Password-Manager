# Secure-Password-Manager

A secure, multi-user password manager built with Node.js. This password manager leverages cryptographic techniques to securely store and manage passwords, preventing common attacks such as swap attacks and rollback attacks.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Cryptographic Security](#cryptographic-security)
- [Questions & Answers](#questions--answers)
- [Future Enhancements](#future-enhancements)

---

## Overview
This project implements a secure password manager that:
- Encrypts passwords using AES-GCM for confidentiality.
- Uses HMAC hashing for domain privacy.
- Detects tampering and rollback attacks with SHA-256 checksums.
- Supports multi-user access for specific shared entries.

The password manager is built using **Node.js** to leverage its cryptographic libraries and provide efficient handling of asynchronous operations. Node.js allows the use of WebCrypto, ensuring modern and secure cryptographic operations.

## Features
- **Password Encryption**: Ensures passwords are stored securely.
- **Domain Privacy**: Hashes domain names to prevent information leakage.
- **Integrity Protection**: Uses SHA-256 to prevent tampering and rollback attacks.
- **Multi-User Support**: Allows specific entries to be shared among users without compromising each user’s private data.

## Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/your-username/secure-password-manager.git
   cd secure-password-manager

2. **Install Dependencies Make sure you have Node.js installed, then run**
   ```bash
   npm test

## Usage
1. **Run Tests: To run the test suite:**
   ```bash
   npm test

2. **Basic Usage: Here's a quick example of using the password manager:**
   ```javascript
   const { Keychain } = require('./password-manager');

(async () => {
    // Initialize a new keychain
    const keychain = await Keychain.init('mySecurePassword');

    // Set and retrieve a password
    await keychain.set('example.com', 'myExamplePassword');
    const retrievedPassword = await keychain.get('example.com');
    console.log("Retrieved password:", retrievedPassword);
})();

##Project Structure
```bash.
├── lib.js                  # Utility functions for cryptography
├── password-manager.js     # Main password manager implementation
├── package.json            # Dependencies and scripts
├── README.md               # Project documentation
└── test
    └── test-password-manager.js  // Test suite


##Cryptographic Security

   
