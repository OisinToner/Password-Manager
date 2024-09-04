## IMPORTANT INFO ##
#Password = AdminPassword123
#Encryption key.key file best stored on secure server or portable drive

from cryptography.fernet import Fernet  # --> Fernet used for encryption
from base64 import urlsafe_b64encode    # --> Converts the binary hash into base64 for fernet
from hashlib import sha256              # --> Turns password into hash number that (with salt) ensures its secure

''' --> this function was used to generate the encryption key
        and is only to be used once when creating the first
        master password. <--
def write_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key) '''

def load_key(): # --> Reading the encryption key <--
    with open("key.key", "rb") as file:
        key = file.read()
    return key

def derive_key(master_pwd, salt=b'some_salt'):  #Addition research was heavily required - *YOU MUST UNDERSTAND SALT*
    # --> Derives a key from the master password and salt <--
    return urlsafe_b64encode(sha256(master_pwd.encode() + salt).digest())

master_pwd = input("Enter master password: ")
''' write_key() --> Used to write key
                    #key & password & text to encrypt = rnd text
                    #rnd txt & key & password = txt to encrypt <--  '''
key = load_key()  # --> Loads the stored key <--
derived_key = derive_key(master_pwd)  # --> Derives the key using the master password <--
fer = Fernet(derived_key)

def view(): # --> function to view passwords stored in passwords file
    with open("Passwords.txt", "r") as f:
        for line in f.readlines():
            data = line.rstrip()
            user, enc_passw = data.split("|")
            try: # --> Try/ Except used to avoid crashing while decrypting file <--
                decrypted_passw = fer.decrypt(enc_passw.encode()).decode() # --> decrypting passwords with key <--
                print(f"Account name: {user} \t=\tAccount password: {decrypted_passw}")
            except Exception as e:
                print(f"Could not decrypt password for {user}: {e}")

def add(): # --> function to add new account & password
    name = input("Account name/type: ")
    pwd = input("Account password: ")

    with open("Passwords.txt", "a") as f:
        encrypted_pwd = fer.encrypt(pwd.encode()).decode()
        f.write(name + "\t|\t" + encrypted_pwd + "\n")

while True:
    mode = input("Would you like to add a new password or view existing ones (view, add, Q to quit)? ").lower()
    if mode == "q":
        print("\nProgram ending...\t\tThank you")
        break
    elif mode == "view":
        view() # --> calls the view passwords function <--
    elif mode == "add":
        add() # --> calls the add password function <--
    else:
        print("Invalid Input")
        continue