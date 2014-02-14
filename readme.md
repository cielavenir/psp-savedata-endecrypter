## PSP SaveData En/Decrypter on PC (GPLv3+)
- kirk-engine (C) draan / proxima
- jpcsp (C) jpcsp team, especially CryptoEngine by hykem
- ported by popsdeco (aka @cielavenir)

### Acknowledgement
- referred SED-PC to fix the hashing algorithm

### What is better than SED-PC?
- This can generate PARAM.SFO hash in mode 4.

### Binary Distribution
- https://www.dropbox.com/s/mj92ccgvwoit746/savedata-endecrypter/

### Building

#### Get libkirk
- Attached from 0.0.1 (to comply GPL)

#### jpcsp backend
- ./compile.sh
- or, gcc -O2 endecrypter_jpcsp.c libkirk/*.c

#### PPSSPP backend
- gcc -O2 endecrypter_ppsspp.cpp libkirk/*.c -lstdc++
