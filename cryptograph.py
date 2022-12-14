import base64
import hashlib, binascii, os
from platform import system
from cryptography.fernet import Fernet, InvalidToken
import getpass

class Crypto():
    def __init__(self):
        self.path = os.getcwd()
        
        if system().lower() == 'windows':
            self.path_seperator = '\\'
            self.salt_path = '\\nodelete\\salt'
        else:
            self.path_seperator = '/'
            self.salt_path = '/nodelete/salt'


        self.nodelete_folder_name = '__do_not_delete__' + self.path_seperator
        self.nodelete_path = self.path + self.path_seperator + self.nodelete_folder_name
        self.salt_path = self.nodelete_path + 'salt'
        self.ignore = [self.nodelete_folder_name[:-2], 'env', '.git', '.gitignore', 'README.md', 'cryptograph.py', 'test.py', '__do_not_delete__', '__pycache__']
        self.partially_encrypted = False

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

    def check_password(self, key=None):
        """
        only for internal use
        """
        if key:
            with open(self.nodelete_path + 'passcheck.txt', 'rb') as f:
                encrypted_string = f.read()
        
        if self.decrypt(encrypted_string, key):
            return True
        
        print('\nWrong password.\n')
        return False


    def passinput(self, first_time=False):
        print(('\nEnter' if first_time==False else '\nChoose') + ' your password:')
        password = getpass.getpass('> ')
        if first_time:
            print('Confirm your password:')
            password_confirm = getpass.getpass('> ')
            if password == password_confirm:
                return password
            else:
                print('Passwords do not match.\n')
                return self.passinput(first_time=first_time)
        return password

    def check_state(self):
        import importlib
        state_mod = importlib.import_module(self.nodelete_folder_name[:-1] + '.state')
        
        return state_mod.state
    
    def change_state(self, state):
        with open(self.nodelete_path + 'state.py', 'w') as f:
            f.write(f'state = \"{state}\"\n')
    
    def update_ignore(self):
        import importlib
        ignore_mod = importlib.import_module(self.nodelete_folder_name[:-1] + '.ignore')
        self.ignore = ignore_mod.ignore

    def check_file_encrypted(self, filename):
        if filename[:11] == '[encrypted]':
            return True
    
    def ed_all(self, state, dir_list, path, key):
            if dir_list.__len__() <= 0:
                print(f'\nNo files to encrypt / decrypt. If your file was ignored, check the ignore list:\n{self.nodelete_path}ignore.py')
            
            if state == 'various':
                print('\nAll files are only partially encrypted (according to cached state). Trying to decrypt all nessecary files at first.\n')
                # TODO: Implement
                for i in dir_list:
                    current_file = dir_list[i]    
                    if self.check_file_encrypted(current_file):
                        # try:
                            self.decrypt_file(current_file, path, key)
                        # except Exception as e:
                            # print(e)
                            # return 0
                
                print('\nShould all files left decrypted or should they be encrypted? [d/e]')

                ed_input = input('> ')
                print('\n')

                if ed_input.lower() == 'e':
                    encrypt_count = 0
                    for file in dir_list:
                        current_file = dir_list[file]
                        if self.encrypt_file(current_file, path, key) != False:
                            encrypt_count += 1
                    
                    if not self.partially_encrypted:
                        print(f'\nEncrypted {str(encrypt_count)} files.')
                        self.change_state('encrypted')
                    else:
                        print(f'\nAn unknown amount of files could not be encrypted (see previous outputs for error output). Processed {str(encrypt_count)} files.')
                        self.change_state('various')
                        self.partially_encrypted = False
       
                elif ed_input.lower() == 'd':
                    self.change_state('decrypted')
                else:
                    print('Invalid input.\n')
                    self.ed_all(state, dir_list, path, key)
                    return
            
            if state == 'decrypted':
                print('\nAll files are decrypted (according to cached state). Trying to encrypt all files...\n')
                encrypt_count = 0
                for i in dir_list:
                    current_file = dir_list[i]
                    if self.check_file_encrypted(current_file):
                        self.change_state('various')
                        print('\nA file is already encrypted, despite internal state was \'decrypted\'. Changed state to \'various\'.')
                        self.ed_all('various', dir_list, path, key)
                        return
                    if self.encrypt_file(current_file, path, key) != False:
                        encrypt_count += 1

                if not self.partially_encrypted:
                    print(f'\nEncrypted {str(encrypt_count)} files.')
                    if encrypt_count != 0:
                        self.change_state('encrypted')
                else:
                    print(f'\nAn unknown amount of files could not be encrypted (see previous outputs for error output). Processed {str(encrypt_count)} files.')
                    self.change_state('various')
                    self.partially_encrypted = False


            if state == 'encrypted':
                print('\nAll files are encrypted (according to cached state). Trying to decrypt all files.\n')
                decrypt_count = 0
                for i in dir_list:
                    current_file = dir_list[i]
                    # TODO: Implement
                    if self.check_file_encrypted(current_file):
                        self.decrypt_file(current_file, path, key)
                        decrypt_count += 1
                print('\nDecrypted ' + str(decrypt_count) + ' files.')
                self.change_state('decrypted')



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
            return None

        self.update_ignore()

        count = 0

        dir_list = {}

        for i in os.listdir():
            
            if i[-3:] != '.py' and i not in self.ignore: 
                dir_list.update({count: i})

            count += 1

        print('\nWhat type of encryption / decryption do you want to use?')
        print('[1] encrypt / decrypt all')
        print('[2] encrypt / decrypt some and show contents in terminal')
        usrinput = input('> ')
        if usrinput == '1':
            not_crypt_count = 0

            state = self.check_state()

            self.ed_all(state, dir_list, path, key)


                  
        elif usrinput == '2':

            print('\nFunctionality not implemented yet')
            # TODO: Implement
            # print('\nwhich file should be decrypted / encrypted?')
            # keylist = []
            # for i in dir_list:
            #     print('[' + str(i) + ']' + ': ' + dir_list[i])
            #     keylist.append(i)
            # chosen_file = input('> ')

            # if chosen_file in keylist:
                
            #     chosen_file = dir_list[chosen_file]
            #     if chosen_file[:11] == '[encrypted]':
            #         chosen_file = chosen_file[12:]
            #         pointer_position = chosen_file.find('].')
            #         encrypted_filename = chosen_file[:pointer_position]

            #         decrypted_filename = self.decrypt(encrypted_filename, key)
            #         if not decrypted_filename:
            #             raise Exception('Wrong password')
            #         decrypted_filename = decrypted_filename.encode('utf-8')

            #         with open(path + self.path_seperator + encrypted_filename, 'rb') as f:
            #             encrypted_content = f.read()
                    
            #         decrypted_content = self.decrypt(encrypted_content, key)
            #         if not decrypted_content:
            #             raise Exception('Wrong password')
            #         decrypted_content = decrypted_content.encode('utf-8')

            #         with open(path + self.path_seperator + decrypted_filename, 'w') as f:
            #             f.write(decrypted_content)

            #         os.remove(path + self.path_seperator + chosen_file)
            #     else:
            #         decrypted_filename = chosen_file
            #         with open(path + self.path_seperator + chosen_file, 'r') as f:
            #             decrypted_content = f.read()
                    
            #         encrypted_filename = self.encrypt(decrypted_filename, key)
            #         encrypted_content = self.encrypt(decrypted_content, key)

        else:
            print('Invalid input.\n')
            self.check_path(path)



            
        



    def setup_path(self, path):
        os.mkdir(self.nodelete_folder_name)
        self.salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
        with open(self.salt_path, 'wb') as f:
            f.write(self.salt)
        with open(self.nodelete_path + self.path_seperator + 'requirements.txt', 'w') as f:
            f.write('cryptography==37.0.4')
        with open(self.nodelete_path + 'passcheck.txt', 'wb') as f:
            f.write(self.encrypt('test', self.hash_password(self.passinput(first_time=True).encode())))
        with open(self.nodelete_path + 'state.py', 'w') as f:
            f.write('state = \"decrypted\"\n')
        ignore_filenames = ''
        for i in self.ignore:
            ignore_filenames += '\'' + i + '\', '
        ignore_filenames = ignore_filenames[:-2]
        with open(self.nodelete_path + 'ignore.py', 'w') as f:
            f.write(f'ignore = [{ignore_filenames}]\n')



    def encrypt(self, content_decrypted, key):
        key = bytes(key)
        f = Fernet(key)
        try:
            try:
                encrypted = f.encrypt(content_decrypted)
            except TypeError:
                encrypted = f.encrypt(content_decrypted.encode()) # convert to type bytes
            return encrypted
        except InvalidToken:
            return False
    
    def encrypt_file(self, decrypted_filename, path, key):
        try:
            if not decrypted_filename.__contains__('.'): # TODO: Change to be able to encrypt folders
                return False
            print(f'Encrypting file {decrypted_filename}...')
            encrypted_filename = self.encrypt(decrypted_filename.encode(), key)
            if not encrypted_filename:
                raise Exception(f'An error occured while encrypting the filename \'{decrypted_filename}\'')
            encrypted_encoded_filename = base64.urlsafe_b64encode(encrypted_filename) # FIXME: potential bug here
            with open(path + self.path_seperator + decrypted_filename, 'rb') as f:
                decrypted_content = f.read()
            encrypted_content = self.encrypt(decrypted_content, key)
            if not encrypted_content:
                raise Exception(f'An error occured while encrypting the content of \'{decrypted_filename}\'')
            with open(path + self.path_seperator + '[encrypted][' + encrypted_encoded_filename.decode() + ']', 'wb') as f:
                f.write(encrypted_content)
            os.remove(path + self.path_seperator + decrypted_filename)
        except OSError as e:
            print(f'Due to an error, the file \'{decrypted_filename}\' could not be encrypted. Exception Output: {str(e)}')
            self.partially_encrypted = True

    def decrypt(self, content_encrypted, key):
        try:
            if content_encrypted == None:
                return content_encrypted
            else:    
                f = Fernet(key)
                decrypted = f.decrypt(bytes(content_encrypted))
                try:
                    decrypted_decoded = decrypted.decode()
                except UnicodeDecodeError:
                    decrypted_decoded = decrypted
                return decrypted_decoded
        except InvalidToken:
            return False

    def decrypt_file(self, filename, path, key):
        encrypted_filename = filename[12:]
        pointer_position = encrypted_filename.find(']', 13)
        encrypted_filename = encrypted_filename[:pointer_position]

        decrypted_filename = self.decrypt(base64.urlsafe_b64decode(encrypted_filename), key)
        if not decrypted_filename:
            raise Exception('Wrong password')
        decrypted_filename = decrypted_filename

        with open(path + self.path_seperator + '[encrypted][' + encrypted_filename  + ']', 'rb') as f:
            encrypted_content = f.read()
        
        decrypted_content = self.decrypt(encrypted_content, key)
        if not decrypted_content and decrypted_content != '':
            raise Exception('Wrong password')
        try:    
            decrypted_content = decrypted_content.encode()
        except AttributeError:
            pass

        with open(path + self.path_seperator + decrypted_filename, 'wb') as f:
            f.write(decrypted_content)

        os.remove(path + self.path_seperator + filename)
        
        print('Decrypted file ' + str(decrypted_filename))



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