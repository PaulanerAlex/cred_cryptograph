import base64
import hashlib, binascii, os
from platform import system
from cryptography.fernet import Fernet, InvalidToken

class Crypto():
    def __init__(self):
        self.path = os.getcwd()
        
        if system().lower() == 'windows':
            self.path_seperator = '\\'
            self.salt_path = '\\nodelete\\salt'
        else:
            self.path_seperator = '/'
            self.salt_path = '/nodelete/salt'


        self.nodelete_folder_name = '.do_not_delete' + self.path_seperator
        self.nodelete_path = self.path + self.path_seperator + self.nodelete_folder_name
        self.salt_path = self.nodelete_path + 'salt'
        # if self.check_path():

    def check_salt_availability(self, path=None):
        """
        Checks if a salt is already stored.
        """
        if not path:
            path = self.path
        
        with open(self.salt_path, 'rb') as f:
            self.salt = f.read()
        if self.salt:
            return True
        return False

    def hash_password(self, password):
        """
        Hash a password for storing.
        """

        salt = ''
        if self.check_salt_availability():
            salt = self.salt
        else:
            raise Exception('Salt not available.')
        pwdhash = hashlib.pbkdf2_hmac('sha512', password, 
                                    salt, 100000, dklen=16)
        pwdhash = binascii.hexlify(pwdhash)
        return base64.urlsafe_b64encode(pwdhash)

    def check_password(self, password=None, key=None, count=0):
        """
        only for internal use
        """
        if key:
            with open(self.nodelete_path + 'passcheck.txt', 'rb') as f:
                encrypted_string = f.read()
        
        if self.decrypt(encrypted_string, key):
            return True
        
        print('Wrong password.\n')
        count += 1
        if count < 3:
            self.check_password(password=password, key=key, count=count)
        return False


    def passinput(self, first_time=False):
        print(('\nEnter' if first_time==False else '\nChoose') + ' your password:')
        password = input('> ')
        print('Confirm your password:')
        password_confirm = input('> ')
        if password == password_confirm:
            return password
        if password != password_confirm:
            print('Passwords do not match.\n')
            return self.passinput(first_time=first_time)


    def check_path(self, path=None):
        """
        Checks the path for every requirement.
        """

        if not path:
            path = self.path

        
        if not os.path.exists(self.nodelete_folder_name):
            usrinput = input("\nInitialize Crypto now?\nATTENTION: if Crypto was initialized before, it could delete the key.\n[y/n]\n> ")
            if usrinput.lower() == 'y':
                self.setup_path(path)
            elif usrinput.lower() == 'n':
                return 0
            else:
                print("Invalid input.\n")
                self.check_path(path)


        key = self.hash_password(self.passinput().encode())
        proceed = self.check_password(key=key)

        if not proceed:
            return 0

        count = 0

        for i in os.listdir():

            dir_list = {}
            
            if i[-3:] != '.py':
                dir_list.update({count: i})

            count += 1

        print('What type of encryption / decryption do you want to use?')
        print('[1] encrypt / decrypt all')
        print('[2] encrypt / decrypt some and show contents in terminal')
        usrinput = input('> ')
        if usrinput == '1':
            for i in dir_list:
                current_file = dir_list[i]
                if current_file[:11] == '[encrypted]':
                    current_file = current_file[12:]
                    pointer_position = current_file.find('].')
                    encrypted_filename = current_file[:pointer_position]

                    decrypted_filename = self.decrypt(base64.decode(encrypted_filename), key)
                    if not decrypted_filename:
                        raise Exception('Wrong password')
                    decrypted_filename = decrypted_filename.encode('utf-8')

                    with open(path + self.path_seperator + encrypted_filename, 'rb') as f:
                        encrypted_content = f.read()
                    
                    decrypted_content = self.decrypt(encrypted_content, key)
                    if not decrypted_content:
                        raise Exception('Wrong password')
                    decrypted_content = decrypted_content.encode('utf-8')

                    with open(path + self.path_seperator + decrypted_filename, 'w') as f:
                        f.write(decrypted_content)

                    os.remove(path + self.path_seperator + chosen_file)
                  
            # TODO: implement
        elif usrinput == '2':
            pass
            # TODO: copy functionallity here
        else:
            print('Invalid input.\n')
            self.check_path(path)


        print('which file should be decrypted / encrypted?')
        keylist = []
        for i in dir_list:
            print(i + ':' + dir_list[i])
            keylist.append(i)
        chosen_file = input('> ')

        if chosen_file in keylist:
            
            chosen_file = dir_list[chosen_file]
            if chosen_file[:11] == '[encrypted]':
                chosen_file = chosen_file[12:]
                pointer_position = chosen_file.find('].')
                encrypted_filename = chosen_file[:pointer_position]

                decrypted_filename = self.decrypt(encrypted_filename, key)
                if not decrypted_filename:
                    raise Exception('Wrong password')
                decrypted_filename = decrypted_filename.encode('utf-8')

                with open(path + self.path_seperator + encrypted_filename, 'rb') as f:
                    encrypted_content = f.read()
                
                decrypted_content = self.decrypt(encrypted_content, key)
                if not decrypted_content:
                    raise Exception('Wrong password')
                decrypted_content = decrypted_content.encode('utf-8')

                with open(path + self.path_seperator + decrypted_filename, 'w') as f:
                    f.write(decrypted_content)

                os.remove(path + self.path_seperator + chosen_file)
            else:
                decrypted_filename = chosen_file
                with open(path + self.path_seperator + chosen_file, 'r') as f:
                    decrypted_content = f.read()
                
                encrypted_filename = self.encrypt(decrypted_filename, key)
                encrypted_content = self.encrypt(decrypted_content, key)

            
        



    def setup_path(self, path):
        os.mkdir(self.nodelete_folder_name)
        self.salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
        with open(self.salt_path, 'wb') as f:
            f.write(self.salt)
        with open(self.nodelete_path + self.path_seperator + 'requirements.txt', 'w') as f:
            f.write('cryptography==37.0.4')
        with open(self.nodelete_path + 'passcheck.txt', 'wb') as f:
            f.write(self.encrypt('test', self.hash_password(self.passinput(first_time=True).encode())))
        


    def encrypt(self, content_decrypted, key):
        key = bytes(key)
        f = Fernet(key)
        try:
            encoded_content_decrypted = content_decrypted.encode() # convert to type bytes
            encrypted = f.encrypt(encoded_content_decrypted)
            return encrypted
        except InvalidToken:
            return False

    def decrypt(self, content_encrypted, key):
        try:
            if content_encrypted == None:
                return content_encrypted
            else:    
                f = Fernet(key)
                decrypted = f.decrypt(bytes(content_encrypted))
                decrypted_decoded = decrypted.decode()
                return decrypted_decoded
        except InvalidToken:
            print("[crypt.crypt.decrypt()                             ] Wrong password")
            return False

# from Crypto.Cipher import AES
# import os
# import random
# import struct
 
 
# def decrypt_file(key, filename, chunk_size=24*1024):
#     output_filename = os.path.splitext(filename)[0]
#     with open(filename, 'rb') as infile:
#         origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
#         iv = infile.read(16)
#         decryptor = AES.new(key, AES.MODE_CBC, iv)
#         with open(output_filename, 'wb') as outfile:
#             while True:
#                 chunk = infile.read(chunk_size)
#                 if len(chunk) == 0:
#                     break
#                 outfile.write(decryptor.decrypt(chunk))
#             outfile.truncate(origsize)
 
 
# def encrypt_file(key, filename, chunk_size=64*1024):
#     output_filename = filename + '.encrypted'
#     iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
#     encryptor = AES.new(key, AES.MODE_CBC, iv)
#     filesize = os.path.getsize(filename)
#     with open(filename, 'rb') as inputfile:
#         with open(output_filename, 'wb') as outputfile:
#             outputfile.write(struct.pack('<Q', filesize))
#             outputfile.write(iv)
#             while True:
#                 chunk = inputfile.read(chunk_size)
#                 if len(chunk) == 0:
#                     break
#                 elif len(chunk) % 16 != 0:
#                     chunk += ' ' * (16 - len(chunk) % 16)
#                 outputfile.write(encryptor.encrypt(chunk))
 
 
##
# Example usage:
##
 
# Encrypt file:
# encrypt_file('abcdefghji123456', 'sample-file.txt')
 
# Decrypt file:
# decrypt_file('abcdefghji123456', 'sample-file.txt.encrypted')

if __name__ == '__main__':
    Crypto().check_path()