import os

file = "C:/Users/catal/PycharmProjects/licenta/main.py.aes"
extension = os.path.splitext(file)[0]
print(extension)

with open(filename, 'rb') as file:
    content = file.read()