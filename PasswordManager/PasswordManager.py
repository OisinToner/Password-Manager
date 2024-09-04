
### IMPORTANT INFO ###
# 1 - I did alot of additional learning to understand salt and the encryption process, you must understand it to understand the code
# 2 - Password = AdminPassword123 - delete password file and run "masterPassSetup.py" to create own password (WRITE IT DOWN)
# 3 - Encryption key.key file best stored on secure server or portable drive

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

def derive_key(master_pwd, salt=b'some_salt'): # --> Addition research was heavily required - *YOU MUST UNDERSTAND SALT*
    # Derives a key from the master password and salt
    return urlsafe_b64encode(sha256(master_pwd.encode() + salt).digest())

def hash_password(password, salt=b'some_salt'): # --> Encrypts the password <--
    # Hashes the password with salt
    return urlsafe_b64encode(sha256(password.encode() + salt).digest()).decode()

def load_stored_password(): # --> Loads the master password from the file <--
    # Load the hashed master password from file
    with open("master_password.txt", "r") as file:
        return file.read().strip()

def view(fer, show_encrypted=False): # --> Reads, decrypts & prints the stored passwords <--
    with open("Passwords.txt", "r") as f:
        for line in f.readlines():
            data = line.rstrip()
            user, pwd = data.split("|")
            if show_encrypted:
                print(f"Account name: {user} \t\t=\t\t Encrypted password: {pwd}")
            else:
                try:
                    decrypted_pwd = fer.decrypt(pwd.encode()).decode()
                    print(f"Account name: {user} \t=\t Account password: {decrypted_pwd}")
                except Exception as e:
                    print(f"Could not decrypt password for {user}: {e}")

def add(fer, is_valid): # --> Function for adding passwords into the txt file <--
    if not is_valid: # -> checks if the master password was correct
        print("Cannot add new passwords.")
        return

    name = input("Account name/type: ")
    pwd = input("Account password: ")

    with open("Passwords.txt", "a") as f:
        encrypted_pwd = fer.encrypt(pwd.encode()).decode() # -> decrypting the password
        f.write(name + "\t|\t" + encrypted_pwd + "\n")

def main(): # --> Main function
    entered_password = input("Enter master password: ")
    stored_password_hash = load_stored_password()  # -> Load the hashed master password

    is_valid = hash_password(entered_password) == stored_password_hash # -> Hashs the entered password and compare with stored hash
    derived_key = derive_key(entered_password)  # -> Derives the key using the entered password

    try: # -> Attempts to create a Fernet object to validate the key
        fer = Fernet(derived_key) if is_valid else None
        if is_valid:
            print("Master password is correct.")
        else:
            print("Master password is incorrect.")
    except Exception as e: # -> Incase program crashes
        print(f"Error creating Fernet object: {e}")
        fer = None

    while True:
        mode = input("Would you like to add a new password or view existing ones (view, add, Q to quit)? ").lower()
        if mode == "q":
            print("\nProgram ending...\t\tThank you")
            break
        elif mode == "view":
            if fer:
                view(fer)
            else:
                view(fer, show_encrypted=True)  # Show encrypted passwords if the master password is incorrect
        elif mode == "add":
            add(fer, is_valid)
        else:
            print("Invalid Input")
            continue

# --> This is the start point of the script
if __name__ == "__main__":
    main()