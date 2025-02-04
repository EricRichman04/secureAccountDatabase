import bcrypt, tkinter as tk, sqlite3, base64
from tkinter import messagebox
#Connecting/Creating the sqlite database 
con = sqlite3.connect("accounts.db")
cur = con.cursor()
#Selecting the table to check if it exist and if not creates the username/password table
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='account'")
result = cur.fetchone()
if not result:
    #The database will create the table account and store the username, password, and salt.
    cur.execute("CREATE TABLE account(username, hash, salt)")

#This function will check the inputted username/password against the database to allow the user to login
def login():
    #Fetch the username/password from the GUI
    username = username_entry.get()
    password = password_entry.get()
    #Checking the database for a match
    if checkForUser(username, password):
        messagebox.showinfo("Success!", "You have successfully logged in!")
    else:
       messagebox.showwarning("Incorrect", "Username/Password combination is incorrect, please try again.")


#This function will check the inputted username/password to add the account to the database if its not
def register():
    username = username_entry.get()
    password = password_entry.get()
    if not checkAccount(username):
        encrypt(username, password)
        messagebox.showinfo("Success!", "You have successfully registered your account!")
    else:
        messagebox.showinfo("Error!", "This account is already in the database")

#Function to check if the username/password is found in the database
def checkForUser(username, password):
    cur.execute("SELECT hash, salt FROM account WHERE username = ?", (username,))
    result = cur.fetchone()
    if result:
        dbPass, dbSalt = result
        #The inputted hashed password to check against the hash in the database
        inputHashPassword = checkEncrypt(password, dbSalt)
        if inputHashPassword == dbPass:
            return True
    else:
        return False

#Function to salt and Hash the passwords and add to database
def encrypt(username, password):
    #Converts password to array of bytes and then adds to the account to the database
    bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(bytes,salt)
    cur.execute("INSERT INTO account (username, hash, salt) VALUES (?, ?, ?)", (username, hash, salt))
    con.commit()

#Returns the value of the inputted password as a hash with the salt
def checkEncrypt(password, salt):
    return bcrypt.hashpw(password.encode('utf-8'), salt)

#Check if the username is already added to the database
def checkAccount(username):
    cur.execute("SELECT username FROM account WHERE username = ?", (username,))
    result = cur.fetchone()
    if result == None:
        return False
    if result[0] == username:
        return True
    else:
        return False


#Create the GUI
gui = tk.Tk()
gui.title("Super Secure Software")
gui.geometry("600x400")

    #Labels
label = tk.Label(gui, text="Please login or register account")
label.pack()

    #Label Frame for Username/Password
label_frame = tk.Frame(gui)
label_frame.pack(side="left", pady=10)

    #Username label & entry 
username_label = tk.Label(gui, text="Username: ")
username_label.pack()
username_entry = tk.Entry(gui, width=30)
username_entry.pack(pady=5)

    #Password label & entry
password_label = tk.Label(gui, text="Password: ")
password_label.pack()
password_entry = tk.Entry(gui, width=30, show='*') #show='*' will replace shown characters with * for privacy
password_entry.pack(pady=5)


    #Button Frame
button_frame = tk.Frame(gui)
button_frame.pack(side="bottom", pady=10)

    #Buttons
login_button = tk.Button(button_frame, text="Login", width=10, command=login)
login_button.pack(side="left", padx=5)

register_button = tk.Button(button_frame, text="Register", width=10, command=register)
register_button.pack(side="right", padx=5)

print_button = tk.Button(button_frame, text="Print DB", width = 10, command=print)
print_button.pack(side="right", padx=5)


gui.mainloop()

    