# Report Lab 2 CAA

## Author

```
Alban Favre
```

### Design

1 master password derived with argon 2 to get master key, to do this we generate master salt.

from master key we make master xsalsa key

we encrypte filename with master xsalsa key, to do this we generate master nonce


-------------

to encrypt file we derive a file keys with argon 2 with master password, to do this we generate a salt per file

from file key we make file xsalsa key

we encrypt each file with its file key, to do this we generate files nonce

--------------

each file has a identifier hash, it is obtained with sha512 from master password and plaintext file name.

--------------

server knows unsalted password hash, as giving it the master password is out of the question. Especially as it can decipher the data. We vant the vault to be in absolute darkness.

this hash will be known as shared secret.

challenge is simple: server generate a nonce, gives it to client. client hash the shared secret and the nonce, send back result, and server verify
