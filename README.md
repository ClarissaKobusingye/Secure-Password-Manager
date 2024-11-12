# 🔒 Secure Password Manager

A secure, multi-user password manager built with Node.js. This password manager leverages cryptographic techniques to securely store and manage passwords, preventing common attacks such as swap attacks and rollback attacks.

## 📑 Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Cryptographic Security](#cryptographic-security)
- [Questions & Answers](#questions--answers)
- [Future Enhancements](#future-enhancements)

---

## 📝 Overview
This project implements a secure password manager that:
- Encrypts passwords using AES-GCM for confidentiality.
- Uses HMAC hashing for domain privacy.
- Detects tampering and rollback attacks with SHA-256 checksums.
- Supports multi-user access for specific shared entries.

The password manager is built using **Node.js** to leverage its cryptographic libraries and provide efficient handling of asynchronous operations. Node.js allows the use of WebCrypto, ensuring modern and secure cryptographic operations.

## ✨ Features
- **Password Encryption**: Ensures passwords are stored securely.
- **Domain Privacy**: Hashes domain names to prevent information leakage.
- **Integrity Protection**: Uses SHA-256 to prevent tampering and rollback attacks.
- **Multi-User Support**: Allows specific entries to be shared among users without compromising each user’s private data.

## ⚙️ Installation

**Clone the Repository**
```bash
git clone https://github.com/your-username/secure-password-manager.git
   
   cd secure-password-manager
 ```
 **Install Dependencies Make sure you have Node.js installed**
```bash 
npm install
```


## Usage
**Run Tests:**
```bash
npm test
```


## 📂 Project Structure
```bash
.
├── lib.js                  # Utility functions for cryptography
├── password-manager.js     # Main password manager implementation
├── package.json            # Dependencies and scripts
├── README.md               # Project documentation
└── test
    └── test-password-manager.js  # Test suite
```

## 🔐 Cryptographic Security
- This password manager follows security best practices to protect stored passwords and prevent attacks:

**AES-GCM Encryption:** Used to securely encrypt each password, ensuring confidentiality.

**HMAC for Domain Privacy:** Hashes domain names to hide them from prying eyes.

**SHA-256 Integrity Check:** Protects against rollback and swap attacks by verifying the entire database's integrity on each load.

**Multi-User Access:** Shared entries are encrypted with a shared key, which is separately encrypted with each user’s master key, allowing access to shared entries while keeping other data isolated.

## ❓Questions & Answers
1.	**Briefly describe your method for preventing the adversary from learning information about the lengths of the passwords stored in your password manager.**
*I was able to achieve this by setting the required length of the password to a fixed length. And this ensures all the password entries are of the same size and their length cant be determined from the ciphertext.*

2.	**Briefly describe your method for preventing swap attacks (Section 2.2). Provide an argument for why the attack is prevented in your scheme.**
*To prevent attempts of unauthorized access.* 

3.	**In our proposed defense against the rollback attack (Section 2.2), we assume that we can store the SHA-256 hash in a trusted location beyond the reach of an adversary. Is it necessary to assume that such a trusted location exists, in order to defend against rollback attacks? Briefly justify your answer**
*Yes, there existed trusted locations, otherwise the adversary would access the KVS and replace its current state to a previous state. This enables rollbacks to go undetected.*

4.	**Because HMAC is a deterministic MAC (that is, its output is the same if it is run multiple times with the same input), we were able to look up domain names using their HMAC values. There are also randomized MACs, which can output different tags on multiple runs with the same input. Explain how you would do the look up if you had to use a randomized MAC instead of HMAC. Is there a performance penalty involved, and if so, what?**
*I would need to store an additional index that maps each domain to its unique, generated MAC. I would then compute the MAC and search through the index to find the associated entry so as to retrieve the password. 
Yes, there is a performance penalty due the additional space required and the additional lookup time required to handle the index.*

5.	**In our specification, we leak the number of records in the password manager. Describe an approach to reduce the information leaked about the number of records. Specifically, if there are k records, your scheme should only leak log2(k) (that is, if k1 and k2 are such that log2(k1) = log2(k2) , the attacker should not be able to distinguish between a case where the true number of records is k1 and another case where the true number of records is k2).**
*By storing the data in blocks of consistent sizes such that even if a group has less data than needed fillers can be used to mislead an adversary.*

6.	**What is a way we can add multi-user support for specific sites to our password managersystem without compromising security for other sites that these users may wish to store passwords of? That is, if Alice and Bob wish to access one stored password (say for nytimes) that either of them can get and update, without allowing the other to access their passwords for other websites.**
*By using separate encryption keys for shared and private entries. Alice and Bob will have separate encryption keys for private data, so that neither of them can access the other’s private data. But for shared data, they will both have a encryption key that share. And this shared key is decrypted by the private master key.*


## 🚀 Future Enhancements
- Add UI: Develop a front-end interface for ease of use.

- Extend Multi-User Functionality: Expand on multi-user access controls and permissions.

- Backup and Restore: Add backup and restore capabilities for added reliability.

### Tips for Contributing

If you would like to contribute to this project, please submit a pull request or open an issue for any bugs or feature suggestions. We welcome community feedback and collaboration!

---
