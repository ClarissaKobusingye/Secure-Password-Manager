"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  
  constructor() {
    this.data = { 
    kvs: {},
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
    };
    this.secrets = {
    
    encryptionKey: null,
    hmacKey: null,
      
    };

    //throw "Not Implemented!";
  };

 
  static async init(password) {
    
   const salt = getRandomBytes(16);  // Generate a random salt for PBKDF2
    const passwordBuffer = stringToBuffer(password);

    // Import the password as key material
    const keyMaterial = await subtle.importKey(
        "raw",
        passwordBuffer,
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    // Derive a master key with PBKDF2
    const masterKey = await subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );

    // Derive HMAC key
    const hmacKey = await subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"]
    );

    // Create a new Keychain instance
    const keychain = new Keychain();
    keychain.secrets.encryptionKey = masterKey;
    keychain.secrets.hmacKey = hmacKey;
    keychain.data.salt = encodeBuffer(salt);  // Store salt in the keychain

    return keychain;
    
    //throw "Not Implemented!";
  }

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */
  static async load(password, repr, trustedDataCheck) {
    const keychainData = JSON.parse(repr);
    const salt = decodeBuffer(keychainData.salt);
    const passwordBuffer = stringToBuffer(password);

    // Import the password as key material
    const keyMaterial = await subtle.importKey(
        "raw",
        passwordBuffer,
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    // Derive AES-GCM and HMAC keys
    const encryptionKey = await subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );

    const hmacKey = await subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"]
    );

    // Verify integrity if trustedDataCheck is provided
    if (trustedDataCheck) {
        const hash = await subtle.digest("SHA-256", stringToBuffer(repr));
        if (bufferToString(hash) !== trustedDataCheck) {
            throw new Error("Integrity check failed");
        }
    }

    try {
    // Attempt to validate decryption using a record from kvs as a check
    for (const record of Object.values(keychainData.kvs)) {
        const iv = decodeBuffer(record.iv);
        const encryptedValue = decodeBuffer(record.value);
        await subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            encryptionKey,
            encryptedValue
        );
        // If decryption is successful, break out of the loop
        break;
    }
} catch (error) {
    // If decryption fails due to an incorrect password, throw an error
    throw new Error("Incorrect password");
}

    // Create and return a valid Keychain instance if the password is correct
    const keychain = new Keychain();
    keychain.data.kvs = keychainData.kvs;
    keychain.secrets.encryptionKey = encryptionKey;
    keychain.secrets.hmacKey = hmacKey;
    keychain.data.salt = encodeBuffer(salt);

    return keychain;
}


  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    */ 
  async dump() {
  const serializedData = JSON.stringify(this.data);
    const hashBuffer = await subtle.digest("SHA-256", stringToBuffer(serializedData));
    const hashString = bufferToString(hashBuffer);

    return [serializedData, hashString];
  
    //throw "Not Implemented!";
  };

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
  // Hash the domain name with HMAC
    const nameHashBuffer = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
    const nameHash = encodeBuffer(nameHashBuffer);

    // Look up in KVS
    const record = this.data.kvs[nameHash];
    if (!record) {
        return null;
    }

    // Decrypt the password
    const iv = decodeBuffer(record.iv);
    const encryptedValue = decodeBuffer(record.value);
    const decryptedValueBuffer = await subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        this.secrets.encryptionKey,
        encryptedValue
    );

    return bufferToString(decryptedValueBuffer);

    //throw "Not Implemented!";
  };

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager.
  *
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  async set(name, value) {
  const nameHashBuffer = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
    const nameHash = encodeBuffer(nameHashBuffer);

    // Encrypt the password value using AES-GCM
    const iv = getRandomBytes(12);  // AES-GCM IV
    const valueBuffer = stringToBuffer(value);
    const encryptedValueBuffer = await subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        this.secrets.encryptionKey,
        valueBuffer
    );

    const encryptedValue = encodeBuffer(encryptedValueBuffer);
    const encodedIV = encodeBuffer(iv);

    // Store in the KVS
    this.data.kvs[nameHash] = { iv: encodedIV, value: encryptedValue };

    //throw "Not Implemented!";
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
  const nameHashBuffer = await subtle.sign("HMAC", this.secrets.hmacKey, stringToBuffer(name));
    const nameHash = encodeBuffer(nameHashBuffer);

    if (this.data.kvs[nameHash]) {
        delete this.data.kvs[nameHash];
        return true;
    }

    return false;
    throw "Not Implemented!";
  };
};

module.exports = { Keychain }
