Total hours: 3ish coding + 1 toying with the math

Problem 37: If the client sets their public key Ato 0 or any multiple of N then the server will always calculate a shared secret of 0. Meaning, you can successfully log in without any knowledge of the password. Without a safeguard for this the attacker could login for any account by manipulating the public key K generation to always hash 0. 