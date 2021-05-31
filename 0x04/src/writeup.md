![](assets/images/banner.png)



<img src="assets/images/htb.png" style="margin-left: 20px; zoom: 60%;" align=left />    	<font size="10">Passphrase-me</font>

​		31<sup>th</sup> May 2021

​		Challenge Author(s): Murilo ([trusted-ws](https://github.com/trusted-ws]trusted-ws))

### Description

This challenge will ask you for a passphrase and a 4 digits PIN code. If the input is validated you will be able to get the flag. And the only thing that you know is that the first char of the passphrase is 'c'.

### Objective

Analyse the assembly routine and find the logic behind the encryption algorithms to figure out the passphrase and PIN code to gain access to the flag.

### Difficulty:

`Hard`

### Flag:

`HTB{0x04_Your_Sk1lls_R_am4z1ng}`

# Challenge

When executed, the program prompts the entry of a "passphrase" and a PIN, if in cases where the data entered is inconsistent, the program displays the message
“Wrong passphrase or PIN!” and returns with a status code of “1”.

Based on that PIN have 4 integer digits, we can assume the PIN value is between 1000 and 9999. It's because any value less than 1000 contains only 3 digits and a starting value with the digit 0 (zero), it's not considered a valid 4 digit integer type value.

The total number of possible combinations in this context will be 9.000 possibilities.

So to create a brute-force script to figure out the correct PIN we will need extract the char array containing encrypted “passphrase”.
So we can check if the result of an XOR operation of the first character of passphrase results in char “c”. If it simply results we will perform the complete decryption of the array that will result in the correct "passphrase". 

# Solver

```python
def decrypt(array: list, key: int) -> str:
    return ''.join([chr(c^key) for c in array])

def main():

    """
    We know:

    I) First char of passphrase is 'c'.
    II) PIN has 4 digits (Integer).

    To figure out the Passphrase and PIN we had to extract the
    encrypted passphrase from the binary and then brute force it.

    To solve we just need to rewrite the decryption algorithm found
    on the Assembly code.
    """

    # Extracted array containing the encrypted 'passphrase'.
    passphrase = [0x48d, 0x486, 0x48b, 0x499, 0x48c, 0x48f, 0x48d, 0x48d, 0x48f]

    # We also know that PIN is between 1000-9999 (4 digits).
    for i in range(1000, 9999+1):
        o = i ^ passphrase[0]
        
        # Based on (I) we know that: p[0] (0x48d) = 'c'
        if(chr(o) == 'c'):
            print(f'Passphrase: {decrypt(passphrase, i)}')
            print(f'PIN: {i}')

if(__name__ == '__main__'):
    main()

```
Inputting the correct data will result in a Flag.
