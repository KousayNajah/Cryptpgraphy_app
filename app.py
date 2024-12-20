from flask import Flask, render_template, request
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import binascii

app = Flask(__name__)

# Affine Cipher Functions
def Prepare(phraseClair):
    L1 = ["à", "éè", "ù", "ç"]
    L2 = ["A", "E", "U", "C"]
    i = 0
    for mot in L1:
        ch = L2[i]
        for l in mot:
            phraseClair = phraseClair.replace(l, ch)
        i += 1
    return phraseClair.upper()

def cryptage(phraseClair):
    phraseClair = Prepare(phraseClair)
    encrypted_message = ""
    b, a = 3, 17
    for char in phraseClair:
        if char.isalpha():
            nbre_char_crypte = (((ord(char) - ord('A')) * a + b) % 26)
            encrypted_message += chr(nbre_char_crypte + ord('A'))
        else:
            encrypted_message += char
    return encrypted_message

def decryptage(phraseClair):
    phraseClair = Prepare(phraseClair)
    decrypted_message = ""
    b, a = 3, 17
    a_inv = pow(a, -1, 26)
    for char in phraseClair:
        if char.isalpha():
            nbre_char_crypte = (a_inv * (ord(char) - ord('A') - b)) % 26
            decrypted_message += chr(nbre_char_crypte + ord('A'))
        else:
            decrypted_message += char
    return decrypted_message

# César Cipher Functions
def cesar_encrypt(text, offset):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    text = text.upper()
    result = ""
    for char in text:
        if char in alphabet:
            idx = (alphabet.index(char) + offset) % 26
            result += alphabet[idx]
        else:
            result += char
    return result

def cesar_decrypt(text, offset):
    return cesar_encrypt(text, -offset)

# Vigenère Cipher Functions
def vigenere_encrypt(text, key):
    text = text.upper()
    key = key.upper()
    result = ""
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[i % len(key)]) - ord('A')
            result += chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    text = text.upper()
    key = key.upper()
    result = ""
    for i, char in enumerate(text):
        if char.isalpha():
            shift = ord(key[i % len(key)]) - ord('A')
            result += chr(((ord(char) - ord('A') - shift) % 26) + ord('A'))
        else:
            result += char
    return result

# RSA Cipher Functions
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key.decode('utf-8'), private_key.decode('utf-8')

def rsa_encrypt(public_key, message):
    public_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return binascii.hexlify(encrypted_message).decode()

def rsa_decrypt(private_key, encrypted_message):
    private_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(private_key)
    encrypted_message = binascii.unhexlify(encrypted_message)
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    return decrypted_message

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/get_method_form/<cipher>', methods=['GET'])
def get_method_form(cipher):
    if cipher == 'cesar':
        return render_template('cesar_form.html')
    elif cipher == 'affine':
        return render_template('affine_form.html')
    elif cipher == 'vigenere':
        return render_template('vigenere_form.html')
    elif cipher == 'rsa':
        return render_template('rsa_form.html')
    return "Cipher not found", 404

@app.route('/cesar', methods=['POST'])
def cesar_cipher():
    text = request.form['text']
    offset = int(request.form['offset'])
    action = request.form['action']

    if action == "encrypt":
        result = cesar_encrypt(text, offset)
    elif action == "decrypt":
        result = cesar_decrypt(text, offset)

    return {"result": result}

@app.route('/affine', methods=['POST'])
def affine_cipher():
    text = request.form['text']
    action = request.form['action']

    if action == "encrypt":
        result = cryptage(text)
    elif action == "decrypt":
        result = decryptage(text)

    return {"result": result}

@app.route('/vigenere', methods=['POST'])
def vigenere_cipher():
    text = request.form['text']
    key = request.form['key']
    action = request.form['action']

    if action == "encrypt":
        result = vigenere_encrypt(text, key)
    elif action == "decrypt":
        result = vigenere_decrypt(text, key)

    return {"result": result}

@app.route('/rsa', methods=['POST'])
def rsa_cipher():
    action = request.form['action']

    if action == 'generate_keys':
        public_key, private_key = generate_rsa_keys()
        return {"public_key": public_key, "private_key": private_key}

    elif action == 'encrypt':
        public_key = request.form.get('public_key')
        message = request.form.get('message')
        if not public_key or not message:
            return {"error": "Public key and message are required."}, 400
        try:
            result = rsa_encrypt(public_key, message)
            return {"result": result}
        except Exception as e:
            return {"error": str(e)}, 500

    elif action == 'decrypt':
        private_key = request.form.get('private_key')
        encrypted_message = request.form.get('encrypted_message')
        if not private_key or not encrypted_message:
            return {"error": "Private key and encrypted message are required."}, 400
        try:
            result = rsa_decrypt(private_key, encrypted_message)
            return {"result": result}
        except Exception as e:
            return {"error": str(e)}, 500

    return {"error": "Invalid action."}, 400

if __name__ == '__main__':
    app.run(debug=True)
