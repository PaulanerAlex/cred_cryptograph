# Credential encryptor

An file encryption tool, that allows you to hide important credentials, secrets, etc. on linux or windows.

## setup

1. install a global python version (min. python 3.1.0)
2. use `pip install cryptography` to add the needed package to python

## usage

1. copy file to desired folder
2. use `python cryptograph.py` in the folder to start the program

__Attention:__ Every instance of this program creates its own salt for encrypting files, so every instance can only encrypt files that where encrypted by this instance. Dont mix encrypted files that where encrypted by different instances.
