My Safe
===================

Encryption and Decryption Overview
-------------

This project enables the user to encrypt and decrypt a given file. The encryption uses an AES-128 cipher algorithm in CBC mode to provide **confidentiality** (hence the need to generate an **IV** for randomness every time a message is encrypted). To provide **integrity**, a keyed-hash message authentication code (**HMAC**) is also appended to the data. The final message will be a concatenation of [*IV, Ciphertext, HMAC*], in that order.

#### Building JAR

To build and package the application run:
```
$ cd {projectroot}/parent
$ mvn package
```

#### Encrypting

To encrypt a file, use the following commands:
```
$ cd {projectroot}/my-safe
$ java -jar target/my-safe.jar -e data/secret.txt
$ Enter your password:
Created new encrypted file: [.../data/secret.txt].8102
Removed the plaintext file: [.../data/secret.txt]
```

An example *secret.txt* file has been provided in the *data* folder. The program will prompt you for a password (which will be hidden in the command prompt). The original file will be deleted and a new file with the same name will be created with a **.8102** extension - this contains the encrypted message. If the given file already has a *.8102* extension, encryption is skipped and the program will exit. If the given file does not exist, the program will provide an error message.

> **Note:** At no point in the application is the provided password stored as a String object. Java Strings are immutable and stored in a String pool for reusability purposes - potentially for a long duration and therefore poses a security threat.

#### Decrypting

To decrypt a file, use the following commands:
```
$ cd {projectroot}/my-safe
$ java -jar target/my-safe.jar -d data/secret.txt.8102
$ Enter your password:
Restored the plaintext file: [.../data/secret.txt]
Removed the encrypted file: [.../data/secret.txt].8102
```

This will reverse the above encryption process. After it has prompted the used for a password, it will take the encrypted file above attempt to decrypt it. On success, it will restore the original file (without the *.8102* extension) which includes the plain data and delete the encrypted file. If the given file is not an encrypted file (or does not exist), the program will skip decryption and exit. Also, if the provided password does not match the original password that it was encrypted with, it will refuse to decrypt the file and exit.