System Security
===================

Overview
-------------

The following repository contains four Java 8 Maven projects, two of which are command line applications for the coursework - **my-safe** which is the *encryption / decryption* program and **recover** which is the *password cracker* program. The **common** project stores common code used in both *my-safe* & *recover* projects and is therefore included as a Maven dependency in both:

 - common (Contains common code used in *my-safe* and *recover*)
 - **my-safe** (*Coursework one* - encryption / decryption program)
 - parent (Contains the parent pom for building both *my-safe* and *recover*)
 - **recover** (*Coursework two* - password cracker program)

To ensure both programs are built correctly, package them up from the parent folder, shown below.

#### Building JARs
Ensure Maven is installed on the operating system:
```
$ mvn -v
```
Package both applications by running:
```
$ cd {projectroot}/parent
$ mvn package
```
This will build and package both the **recover.jar** and the **my-safe.jar**:
```
[INFO] ------------------------------------------------------------------------
[INFO] Reactor Summary:
[INFO]
[INFO] common ............................................. SUCCESS [  2.878 s]
[INFO] parent ............................................. SUCCESS [  0.000 s]
[INFO] my-safe ............................................ SUCCESS [  0.720 s]
[INFO] recover ............................................ SUCCESS [  0.767 s]
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
```
You can find the JARs in their respective **target** folders:
```
{projectroot}/my-safe/target/my-safe.jar
{projectroot}/recover/target/recover.jar
```
Instructions on running each application can be found in their respective **README.md** files. Both are command line applications and therefore output will be piped to the console.