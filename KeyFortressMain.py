import sqlite3
import bcrypt
import tkinter
from tkinter import ttk, simpledialog
import sv_ttk

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
sv_ttk.set_theme("dark")
root.title("KeyFortress")

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

def passwordVault():
    for widget in root.winfo_children():
        widget.destroy()

    def addLogin():
        url = simpledialog.askstring('Input', 'Website URL:')
        username = simpledialog.askstring('Input', 'Username:')
        password = simpledialog.askstring('Input', 'Password:', show="*")

        insertLogin = '''INSERT INTO passwords(url, username, password)
        VALUES(?, ?, ?)'''

        cursor.execute(insertLogin, (url, username, password))
        db.commit()

        passwordVault()
    
    
    def goToPayment():

        paymentVault()
    
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

    root.geometry("700x350")

    label = ttk.Label(root, text="Password Vault")
    label.grid(column=1, row=0)

def paymentVault():
    for widget in root.winfo_children():
        widget.destroy()

    def addPayment():
        cardName = simpledialog.askstring('Input', 'Card Name:')
        cardHolder = simpledialog.askstring('Input', 'Card Holder:')
        cardNumber = simpledialog.askstring('Input', 'Card Number:')
        ccv = simpledialog.askstring('Input', 'CCV:')
        expirationDate = simpledialog.askstring('Input', 'Expiration Date:')

        insertPayment = '''INSERT INTO payment(cardName, cardHolder, cardNumber, ccv, expirationDate)
        VALUES(?, ?, ?, ?, ?)'''

        cursor.execute(insertPayment, (cardName, cardHolder, cardNumber, ccv, expirationDate))
        db.commit()

        paymentVault()
    
    def goToPassword():
        passwordVault()
    
    addButton = ttk.Button(root, text='+', command= addPayment, style='Bold.TButton')
    addButton.grid(row=0, column=0, pady=10)
    style = ttk.Style()
    style.configure('Bold.TButton', font=('Helvetica', 16, 'bold'))

    goToPasswordButton = ttk.Button(root, text='>', command=goToPassword,style='Bold.TButton')
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


    root.geometry("700x350")

    label = ttk.Label(root, text="Payment Vault")
    label.grid(column=2, row=0)

check = cursor.execute('SELECT * FROM masterpassword')
if cursor.fetchone():
    loginPage()
else:
    createMaster()

root.mainloop()
