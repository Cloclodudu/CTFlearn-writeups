# CTFlearn-writeups
CTFlearn-writeups

 
Encryption Master

"Alright. Serious talk. You need to work pretty hard for this one (unless you are an encryption god.) Well, good luck. https://mega.nz/#!iPgzXIiD!Pkza_S8YUxIXrZ7gdwMcIoufMzi_FjSio3Vx9GuL0ok"

CyberChef
-From Base 64 result:
Nice! Now keep going. 54776f206d6f72652e203031303030313130203031313031303031203031313031313130203031313030303031203031313031313030203030313030303030203031303030313030203031313030313031203031313030303131203031313130303130203031313131303031203031313130303030203031313130313030203031313031303031203031313031313131203031313031313130203030313030303031203030313030303030203031303130303031203030313130303031203031303130303130203031303030313131203031313030313031203030313130303030203031313031313030203031313030313130203031303130303031203031303130313031203030313130303031203031313030313130203031303130313031203031303030313130203031303031303130203031303130303030203031303130313130203031303130313031203031303130303130203031313030313130203031303130313030203030313130303030203031303131303130203031313030313130203031303130313131203031303130313031203030313131303031203031303130313130203031313030313130203031303130303031203030313131313031203030313131313031

-From Hex results :
ÎîTwo more. 01000110 01101001 01101110 01100001 01101100 00100000 01000100 01100101 01100011 01110010 01111001 01110000 01110100 01101001 01101111 01101110 00100001 00100000 01010001 00110001 01010010 01000111 01100101 00110000 01101100 01100110 01010001 01010101 00110001 01100110 01010101 01000110 01001010 01010000 01010110 01010101 01010010 01100110 01010100 00110000 01011010 01100110 01010111 01010101 00111001 01010110 01100110 01010001 00111101 00111101

-From Binary results :
Data is not a valid byteArray: [null,null,154,91,152,...

-Back to From Hex, copy paste the binary part into the imput and use the From Binary :
Final Decryption! Q1RGe0lfQU1fUFJPVURfT0ZfWU9VfQ==

-Copy Paste the part in base 64 and translate it :
CTF{I_AM_PROUD_OF_YOU}

Writed by : Cloclodudu and Asch-sys

--------------------------------------------------------------------------------------------------------------------------------------------------------------------

So many 64s

"Help! My friend stole my flashdrive that had the flag on it. When he gave it back the flag was changed! Can you help me decrypt it? https://mega.nz/#!OHhUyIqA!H9WxSdG1O7eVcCm0dffggNB0-dBemSpBAXiZ0OXJnLk"

CyberChef

Use From Base 64 until you have some plain text : " ABCTF{pr3tty_b4s1c_r1ght?} ".
Now you can detect the flag : CTF{pr3tty_b4s1c_r1ght?}

Writed by : Cloclodudu and Asch-sys

--------------------------------------------------------------------------------------------------------------------------------------------------------------------

RSA Twins!

"https://mega.nz/#!2aBwFCKa!NWQKRIbYzSAU2iwCPNppO7SE92W6sne4FKD3sKE2A-k Aww, twins :). Theyâre so cute! They must be (almost) identical because theyâre the same except for the slightest difference. Anyway, see if you can find my flag. Hint: This is just math. You're probably not going to find any sort of specialized attack."

-By downloading the file you got the values of n, e and c: 

n = 14783703403657671882600600446061886156235531325852194800287001788765221084107631153330658325830443132164971084137462046607458019775851952933254941568056899

e = 65537

c = 684151956678815994103733261966890872908254340972007896833477109225858676207046453897176861126186570268646592844185948487733725335274498844684380516667587

-http://factordb.com

-Factorize n :
p=121588253559534573498320028934517990374721243335397811413129137253981502291629
q=121588253559534573498320028934517990374721243335397811413129137253981502291631

-Now you can create your rsa.py :

#!/usr/bin/env python3
from Cryptodome.Util import number
n = 14783703403657671882600600446061886156235531325852194800287001788765221084107631153330658325830443132164971084137462046607458019775851952933254941568056899
e = 65537
c = 684151956678815994103733261966890872908254340972007896833477109225858676207046453897176861126186570268646592844185948487733725335274498844684380516667587
p = 121588253559534573498320028934517990374721243335397811413129137253981502291629
q = 121588253559534573498320028934517990374721243335397811413129137253981502291631

phi = (p-1)*(q-1)
    
d = number.inverse(e, phi)
    
m = pow(c,d,n)
print(number.long_to_bytes(m))

-In the terminal:
python3 rsa.py 
--> b'flag{i_l0v3_tw1N_pr1m3s}'

Writed by : Cloclodudu and Asch-sys

--------------------------------------------------------------------------------------------------------------------------------------------------------------------

XOR Is Friend Not Food

"Here: \t\x1b\x11\x00\x16\x0b\x1d\x19\x17\x0b\x05\x1d(\x05\x005\x1b\x1f\t,\r\x00\x18\x1c\x0e

I think the flag started with: ctflearn{"

-

Writed by : Cloclodudu and Asch-sys
