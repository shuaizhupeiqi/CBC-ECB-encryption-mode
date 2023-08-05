from flask import Flask, render_template, request, redirect, url_for
from Crypto.Cipher import AES
import binascii
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from flask import flash
import logging
from Crypto.Cipher import AES
import uuid
import binascii
import base64
import json

app = Flask(__name__)


def pad_session(session):

    padding_size = 16 - len(session) % 16
    padding = chr(padding_size) * padding_size
    padded_session = session + padding
    return padded_session

def enc(key,data,iv):
    aes = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = aes.encrypt(data)
    ciphertext = binascii.b2a_hex(ciphertext)
    return ciphertext

def dec(key,c,iv):
    c = binascii.a2b_hex(c)
    aes = AES.new(key, AES.MODE_CBC, iv)
    data = aes.decrypt(c)
    return data


def aes_ecb_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data, AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted).decode()

def aes_ecb_decrypt(key, encrypted):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(binascii.unhexlify(encrypted))
    return unpad(decrypted_data, AES.block_size).decode()

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':

        key = b'aaaaaaaaaaaaaaaa'
        if request.cookies.get('is_admin'):
            is_admin = request.cookies.get('is_admin')
            test = aes_ecb_decrypt(key, is_admin)
            if test == '1':
                flag = 'flag{testforecbvulnerability} '
                return render_template('login.html', flag=flag)
            return render_template('login.html', flag="flag")

        elif request.form['username'] == 'admin' and request.form['password'] == 'admin':
            flag = 'flag{} '
            return render_template('login.html', flag=flag)

        else:
            error = 'Display the flag when the string is_admin quals 1  ---  Your cookie/session is: '
            key = b'aaaaaaaaaaaaaaaa'
            data = request.form['username'].encode() + request.form['password'].encode()  # Two blocks of plaintext
            encrypted = aes_ecb_encrypt(key, data)

            return render_template('login.html', error=error + encrypted)
    return render_template('login.html')

@app.route('/cbc', methods=['GET', 'POST'])


def cbc():
    if request.method == 'POST':
        key = b"testtesttesttest"
        iv = b"1111111111111111"

        session="username:"+request.form['username'] + "password:"+request.form['password'] + "is_admin:"+ '0'
        session = pad_session(session)
        session= session.encode()
        enc_session = enc(key, session, iv)
        if request.cookies.get('is_admin'):
            is_admin = request.cookies.get('is_admin')
            key = b'testtesttesttest'
            iv = b"1111111111111111"
            dec_data = dec(key, is_admin, iv)
            char_after_is_admin = dec_data.split(b"is_admin:")[1][0]
            if (char_after_is_admin==49):
                cot="flag{testcbcattack}"
            else:
                print(dec_data[-1])
                cot = dec_data
            return render_template('cbc.html', flag= cot)
        return render_template('cbc.html', flag=b"session:"+enc_session, info=session)
    else:
        return render_template('cbc.html', flag="Welcome", info="CTF-AES_CBC")



@app.route('/home')
def home():
    return render_template('home.html')

if __name__ == "__main__":
    app.run(host='0.0.0.0',debug=True,port=5001)

