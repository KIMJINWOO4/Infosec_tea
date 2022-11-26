# Infosec_tea
(Input)
argv[2] (select) -> encrypt : -e
                 -> decrypt : -d
argv[3] (mode) -> cbc : cbc
               -> ecb : ecb
argv[4] (filename) 

password

Encrypt mode CBC :

(Tea Encrypt use key) password -> key
(Tea Encrypt use key) CBC Header 32 Byte  + IV + (Tea Encrypt) 32Byte Blocks

Tea encrypt Block ^ IV -> block1
Tea encrypt Block ^ block1 ...

result : filename.tea

Encrypt mode ECB :
(Tea Encrypt use key) ECB Header 32Byte  + (Tea Encrypt use key) 32Byte Blocks

result : filename.tea

Decypt mode CBC :
(Tea Decrypt use key) Header 32Byte == orgin ECB Header 32Byte,
(Tea Decrypt use key) 32Byte Blocks 

result : filename

Decypt mode ECB :
(Tea Decrypt use key) Header 32Byte == orgin CBC Header 32Byte,
(Tea Decrypt use key) Block0 ^ IV = orgin Block0
(Tea Decrypt use key) Block1 ^ Block0(Not Decrypt) = orgin Block1 ...

result : filename
