A login system that is connected to a SQLite3 database. This application stores users account/password in a database that is used to login to the system. This application uses bcrypt to encrypt the data and stores the hashed password value and salt along with the username. This application
stores the database locally on the users device and not on the web. (This application is used to help understand how to generate hash and salt values to be stored in the database, it also familiarizes me with parameterized entries to prevent SQL Injections.

This application uses tkinter to create the GUI, bcrypt for encryption

The functions that this applications have are
***login()*** - This function is for the login button and accepts the entry from username/password and checks the database for the hash value for the entered password

***register()*** - This function is for the register button which adds the entered username/password to the local SQLite3 database

***checkForUser(username, password)*** - This function will check if the entered username/password is in the database to login

***encrypt(username, password)*** - This function encrypts the users password and creates a hash value and salt which is passed back to the register function

***checkEncrypt(password, salt)*** - This function will check if the entered password matches the hashed value of the password for the username in the database

***checkAccount(username)*** - This function checks if the username is already stored in the database and if not passes a True value to add the account to the database.
