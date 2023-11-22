import sqlite3
import bcrypt
import tkinter
from tkinter import ttk, simpledialog, messagebox
import sv_ttk
import os
from cryptography.fernet import Fernet
import random
import string
import pyperclip

# Create key
if os.path.exists('encryption_key.txt'):
    # If the key file exists, read the key
    with open('encryption_key.txt', 'rb') as file:
        key = file.read()
else:
    # If the key file does not exist, generate a new key and save it to the file
    key = Fernet.generate_key()
    with open('encryption_key.txt', 'wb') as file:
        file.write(key)

cipher_suite = Fernet(key)

# Create Database
with sqlite3.connect("information_storage.db") as db:
    cursor = db.cursor()

#Create masterpassword table
cursor.execute('''
CREATE TABLE IF NOT EXISTS masterpassword (
    id INTEGER PRIMARY KEY,
    password TEXT NOT NULL);
''')

#Create password information table
cursor.execute('''
CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL);
''')

#Create payment information table
cursor.execute('''
CREATE TABLE IF NOT EXISTS payment (
    id INTEGER PRIMARY KEY,
    cardName TEXT NOT NULL,
    cardHolder TEXT NOT NULL,
    cardNumber TEXT NOT NULL,
    ccv TEXT NOT NULL,
    expirationDate TEXT NOT NULL);
''')

# Initialize window and set theme
root = tkinter.Tk()
root.iconbitmap("icon.ico")
sv_ttk.set_theme("dark")
root.title("KeyFortress")

# Center window
def centerWindow(root):
    # Update window dimensions
    root.update_idletasks()

    # Get window width and height
    window_width = root.winfo_width()
    window_height = root.winfo_height()

    # Get screen width and height
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()

    # Calculate position coordinates
    x = (screen_width/2) - (window_width/2)
    y = (screen_height/2) - (window_height/2)

    root.geometry('+%d+%d' % (x, y))

# Hash and salt
def hashMasterPassword(input):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(input.encode('utf-8'), salt)
    return hashed

def createMaster():
    root.geometry("400x200")

    label = ttk.Label(root, text="Create Master Password")
    label.config(anchor='center')
    label.pack()

    txt = ttk.Entry(root, width=20, show="*")
    txt.pack()
    txt.focus()

    label1 = ttk.Label(root, text="Re-enter Master Password")
    label1.config(anchor='center')
    label1.pack()

    txt1 = ttk.Entry(root, width=20, show="*")
    txt1.pack()

    errorLabel = ttk.Label(root)
    errorLabel.pack()

    def saveMaster():
        if txt.get() == txt1.get():
            hashedMasterPassword = hashMasterPassword(txt.get())
            # Store the hashed password in the database
            insertMasterPassword = '''INSERT INTO masterpassword(password)
            VALUES(?)'''
            cursor.execute(insertMasterPassword, (hashedMasterPassword,))
            db.commit()

            passwordVault()
        else:
            txt.delete(0, 'end')
            txt1.delete(0, 'end')
            txt.focus()
            errorLabel.config(foreground='red', text="The passwords do not match")

    bttn = ttk.Button(root, text="Submit", command=saveMaster)
    bttn.pack(pady=10)

def loginPage():
    root.geometry("300x150")

    label = ttk.Label(root, text="Enter Master Password")
    label.config(anchor='center')
    label.pack()

    txt = ttk.Entry(root, width=20, show="*")
    txt.pack()
    txt.focus()

    errorLabel = ttk.Label(root)
    errorLabel.pack(pady=2)

    def getMasterPassword():
        cursor.execute('SELECT password FROM masterpassword WHERE id = 1')
        result = cursor.fetchone()
        if result:
            hashed_password_from_db = result[0]
            return hashed_password_from_db
        return None

    def checkPassword():
        entered_password = txt.get()
        hashed_password_from_db = getMasterPassword()

        if hashed_password_from_db and bcrypt.checkpw(entered_password.encode('utf-8'), hashed_password_from_db):
            passwordVault()
        else:
            txt.delete(0, 'end')
            txt.focus()
            errorLabel.config(foreground='red', text="Wrong password")



    bttn = ttk.Button(root, text="Submit", command=checkPassword)
    bttn.pack()

def createTextWidget(root, text, row, column):
    textWidget = tkinter.Text(root, height=1, width=20, borderwidth=0, font=("Helvetica", 10))
    textWidget.insert(1.0, " " + text + " ")
    textWidget.tag_configure("center", justify='center')
    textWidget.tag_add("center", 1.0, "end")
    textWidget.configure(state='disabled')
    textWidget.grid(row=row, column=column)
    
     # Create a Menu widget
    menu = tkinter.Menu(root, tearoff=0)
    menu.add_command(label="Copy", command=lambda: root.clipboard_clear() or root.clipboard_append(textWidget.get("1.0", 'end-1c')))

    # Bind the Menu to the right-click event
    def show_menu(event):
        menu.post(event.x_root, event.y_root)

    textWidget.bind("<Button-3>", show_menu)

def passwordVault():
    for widget in root.winfo_children():
        widget.destroy()

    def addLogin():
        url = simpledialog.askstring('Add Login', 'Website URL:', parent=root)
        username = simpledialog.askstring('Add Login', 'Username:', parent=root)
        password = simpledialog.askstring('Add Login', 'Password:', show="*", parent=root)

        # Encrypt the user input
        url = cipher_suite.encrypt(url.encode())
        username = cipher_suite.encrypt(username.encode())
        password = cipher_suite.encrypt(password.encode())

        insertLogin = '''INSERT INTO passwords(url, username, password)
        VALUES(?, ?, ?)'''

        cursor.execute(insertLogin, (url, username, password))
        db.commit()

        passwordVault()
    
    def delLogin(input):
        cursor.execute('DELETE FROM passwords WHERE id = ?', (input,))
        db.commit()

        passwordVault()
    
    def goToPayment():
        paymentVault()
    
    #Generate password and copy to clipboard
    def generatePassword():
        length = 16
        all_characters = string.ascii_letters + string.digits + string.punctuation
        randomPassword = ''.join(random.choice(all_characters) for _ in range(length))

        pyperclip.copy(randomPassword)

        messagebox.showinfo("Password Generated", "A random password has been generated and copied to the clipboard.")

    addButton = ttk.Button(root, text='*', command= generatePassword, style='Bold.TButton')
    addButton.grid(row=0, column=3, pady=10)
    style = ttk.Style()
    style.configure('Bold.TButton', font=('Helvetica', 16, 'bold'))

    
    #Add info button
    addButton = ttk.Button(root, text='+', command= addLogin, style='Bold.TButton')
    addButton.grid(row=0, column=0, pady=10)
    style = ttk.Style()
    style.configure('Bold.TButton', font=('Helvetica', 16, 'bold'))

    goToPaymentButton = ttk.Button(root, text='>', command=goToPayment,style='Bold.TButton')
    goToPaymentButton.grid(row=0, column=2, pady=10)
    
    #URL, Username, and Password grid formatting
    label = ttk.Label(root, text='URL')
    label.grid(row=2, column=0, padx=80)
    label = ttk.Label(root, text='Username')
    label.grid(row=2, column=1, padx=80)
    label = ttk.Label(root, text='Password')
    label.grid(row=2, column=2, padx=80)

    # Display login information and delete button
    cursor.execute('SELECT * FROM passwords')
    result = cursor.fetchall()
    for index, x in enumerate(result):
        decrypted_url = cipher_suite.decrypt(x[1]).decode()
        decrypted_username = cipher_suite.decrypt(x[2]).decode()
        decrypted_password = cipher_suite.decrypt(x[3]).decode()

        createTextWidget(root, decrypted_url, index+3, 0)
        createTextWidget(root, decrypted_username, index+3, 1)
        createTextWidget(root, decrypted_password, index+3, 2)
        ttk.Button(root, text="Delete", command= lambda input=x[0]: delLogin(input)).grid(row=index+3, column=3)

    root.geometry("725x350")

    label = ttk.Label(root, text="Password Vault")
    label.grid(column=1, row=0)

def paymentVault():
    for widget in root.winfo_children():
        widget.destroy()

    def addPayment():
        cardName = simpledialog.askstring('Add Payment', 'Card Name:', parent=root)
        cardHolder = simpledialog.askstring('Add Payment', 'Card Holder:', parent=root)
        cardNumber = simpledialog.askstring('Add Payment', 'Card Number:', parent=root)
        ccv = simpledialog.askstring('Add Payment', 'CCV:', parent=root)
        expirationDate = simpledialog.askstring('Add Payment', 'Expiration Date:', parent=root)

        # Encrypt the user input
        cardName = cipher_suite.encrypt(cardName.encode())
        cardHolder = cipher_suite.encrypt(cardHolder.encode())
        cardNumber = cipher_suite.encrypt(cardNumber.encode())
        ccv = cipher_suite.encrypt(ccv.encode())
        expirationDate = cipher_suite.encrypt(expirationDate.encode())

        insertPayment = '''INSERT INTO payment(cardName, cardHolder, cardNumber, ccv, expirationDate)
        VALUES(?, ?, ?, ?, ?)'''

        cursor.execute(insertPayment, (cardName, cardHolder, cardNumber, ccv, expirationDate))
        db.commit()

        paymentVault()

    def delPayment(input):
        cursor.execute('DELETE FROM payment WHERE id = ?', (input,))
        db.commit()

        paymentVault()

    def goToPassword():
        passwordVault()

    addButton = ttk.Button(root, text='+', command=addPayment, style='Bold.TButton')
    addButton.grid(row=0, column=0, pady=10)
    style = ttk.Style()
    style.configure('Bold.TButton', font=('Helvetica', 16, 'bold'))

    goToPasswordButton = ttk.Button(root, text='>', command=goToPassword, style='Bold.TButton')
    goToPasswordButton.grid(row=0, column=4, pady=10)

    label = ttk.Label(root, text='Card Name')
    label.grid(row=2, column=0, padx=35)
    label = ttk.Label(root, text='Card Holder')
    label.grid(row=2, column=1, padx=35)
    label = ttk.Label(root, text='Card Number')
    label.grid(row=2, column=2, padx=55)
    label = ttk.Label(root, text='CCV')
    label.grid(row=2, column=3, padx=35)
    label = ttk.Label(root, text='Exp Date')
    label.grid(row=2, column=4, padx=35)


    # Display payment information as a text widget and delete button
    cursor.execute('SELECT * FROM payment')
    result = cursor.fetchall()
    for index, x in enumerate(result):
        decrypted_cardName = cipher_suite.decrypt(x[1]).decode()
        decrypted_cardHolder = cipher_suite.decrypt(x[2]).decode()
        decrypted_cardNumber = cipher_suite.decrypt(x[3]).decode()
        decrypted_ccv = cipher_suite.decrypt(x[4]).decode()
        decrypted_expirationDate = cipher_suite.decrypt(x[5]).decode()

        createTextWidget(root, decrypted_cardName, index+3, 0)
        createTextWidget(root, decrypted_cardHolder, index+3, 1)
        createTextWidget(root, decrypted_cardNumber, index+3, 2)
        createTextWidget(root, decrypted_ccv, index+3, 3)
        createTextWidget(root, decrypted_expirationDate, index+3, 4)
        ttk.Button(root, text="Delete", command=lambda input=x[0]: delPayment(input)).grid(row=index + 3, column=5)

    root.geometry("860x350")
    label = ttk.Label(root, text="Payment Vault")
    label.grid(column=2, row=0)


check = cursor.execute('SELECT * FROM masterpassword')
if cursor.fetchone():
    loginPage()
else:
    createMaster()
centerWindow(root)
root.mainloop()
