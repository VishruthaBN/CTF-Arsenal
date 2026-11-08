Challenge 01: Mod 26



Platform: picoCTF

Category: Cryptography

Difficulty: Beginner

Technique: ROT13



Challenge Overview



The challenge provided an encoded message that needed to be decoded to recover the flag.



Encrypted Message



npnqrzl{arkg\_gvzr\_V'yy\_gel\_2\_ebhaqf\_bs\_ebg13\_5p5f5o36}



Methodology



I identified ROT13 as the likely encoding technique.



ROT13 shifts each alphabetic character by 13 positions through the English alphabet. Numbers, punctuation and symbols remain unchanged.



Solution



I used my CTF Arsenal Python toolkit to decrypt the message:



python main.py caesar decrypt "npnqrzl{arkg\_gvzr\_V'yy\_gel\_2\_ebhaqf\_bs\_ebg13\_5p5f5o36}" --shift 13



Decoded Output



academy{next\_time\_I'll\_try\_2\_rounds\_of\_rot13\_5c5f5b36}



Key Learnings



ROT13 is a Caesar cipher with a shift of 13.



Applying ROT13 twice restores the original text.



Recognizing common encoding patterns is useful in CTF challenges.



I verified the result using my own Python toolkit.



Tools Used



Python 3



CTF Arsenal



PowerShell

