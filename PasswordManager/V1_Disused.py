

from cryptography.fernet import Fernet


def write_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    file = open("key.key", "rb")
    key = file.read()
    file.close()
    print(key)
    return key

master_pwd = input("Enter master password: ")
key = load_key() + master_pwd.encode()
fer = Fernet(key)

write_key() # used to write the initial enctyption key

#key & password & text to encrypt = rnd text
#rnd txt & key & password = txt to encrypt

def view():
    with open("Passwords.txt", "r") as f:
        for line in f.readlines():
            data = line.rstrip()
            user, passw = data.split("|")
            print("Account name:", user, "= Account password: ", fer.decrypt(passw.encode()).decode())


def add():
    name = input("Account name/type: ")
    pwd = input("Account password: ")

    with open("Passwords.txt", "a") as f:
        f.write(name + "\t|\t" + fer.encrypt(pwd.encode()).decode() + "\n")

while True:
    mode = input("Would you like to add new password or view existing ones (view, add, Q to quit)? ").lower()
    if mode == "q":
        print("\nThank you...\t\tProgram ending")
        break
    elif mode == "view":
        view()
    elif mode == "add":
        add()
    else:
        print("Invalid Input")
        continue