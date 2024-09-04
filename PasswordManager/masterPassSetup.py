from hashlib import sha256
from base64 import urlsafe_b64encode

def hash_password(password, salt=b'some_salt'):
    # Hashes the password with salt
    return urlsafe_b64encode(sha256(password.encode() + salt).digest()).decode()

def save_master_password(password):
    hashed_password = hash_password(password)
    with open("master_password.txt", "w") as file:
        file.write(hashed_password)

# Run this script once to save the master password
if __name__ == "__main__":
    password = input("Enter master password to set: ")
    save_master_password(password)
    print("Master password saved.")