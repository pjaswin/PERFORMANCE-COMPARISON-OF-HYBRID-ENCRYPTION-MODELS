# file1 = open("example1.txt", "r")

# file2 = open("exampl1.txt", "r")

# contents1 = file1.read()
# contents2= file2.read()

# matchcount=0

# if len(contents1)==len(contents2):
#     print("both are same size")

# for i in range(len(contents1)):
#     if contents1[i]==contents2[i]:
#         matchcount=matchcount+1
    
# print("percentage ::", matchcount/len(contents1)*100)





with open("sec1.txt", 'rb') as f:
    byte_string1 = f.read()
with open("sec2.txt", 'rb') as f:
    byte_string2 = f.read()
matchcount=0
if len(byte_string1)==len(byte_string2):
  print("both are same size")
for i in range(len(byte_string2)):
    if byte_string1[i]==byte_string2[i]:
        matchcount=matchcount+1 

print("key sensitivity percentage of ECC BLOWFISH ::", matchcount/len(byte_string2)*100)


with open("example1.txt", 'rb') as f:
    byte_string1 = f.read()
with open("exampl1.txt", 'rb') as f:
    byte_string2 = f.read()
matchcount=0
if len(byte_string1)==len(byte_string2):
  print("both are same size")
for i in range(len(byte_string2)):
    if byte_string1[i]==byte_string2[i]:
        matchcount=matchcount+1 

print("key sensitivity percentage of ECC AES ::", matchcount/len(byte_string2)*100)