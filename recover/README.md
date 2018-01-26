Recover
===================

Password Cracking Overview
-------------

This project enables the user to crack a given set of hashed passwords through a combination of dictionary attacks and brute force attacks. The dictionary is populated with prearranged case-insensitive strings found in the *data/dictionary/* directory; *girl_names.txt*, *boy_names.txt* and *word_list_moby_all_moby_words.flat.txt* files. It is then populated with case-sensitive boy and girl names, each with a number between 1-9999 appended to it e.g. *sOphiE654*, *JAck23*. After the dictionary is exhausted, the program will generate four-character, case-sensitive alphanumeric strings that can also contain special characters e.g. *$4Fc*, *H&*1*.

#### Building JAR

To build and package the application run:
```
$ cd {projectroot}/parent
$ mvn package
```

#### Crack passwords

To start cracking a list of hashed passwords run the following commands (the data directory is provided):
```
$ cd {projectroot}/recover
$ java -jar target/recover.jar -i data/hashes.txt -o data/output.txt -d data/dictionary
8 hash(s) analysed, 8 password(s) found.
Execution time: 14.829 secs.
Attempts: 13089934
```

This will first read all hashed passwords from the **hashes.txt** file and loop until all passwords have been cracked or the dictionary has been exhausted (it will currently find all passwords for the coursework). Once a password has been cracked it will write the original hash and plain text password to the **output.txt** file in the following format:
```
[hash] [password]
```
The original pre-optimised results cracked all **8** hashed passwords in **XXX seconds** and generated around **35 million** test passwords. 

To simulate the danger and effect of an attacker only knowing the first letter of your password (perhaps through shoulder surfing), the alphabet array was modified so that the '*@*' and '*K*' characters are at the start of the alphabet. After this small change, all hashed passwords were found in **14.829** seconds using only **13 million** test passwords.