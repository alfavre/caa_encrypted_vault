# caa_encrypted_vault

## Author Alban Favre

### Intro

This is a practical rust work for school.

### Objectives

Implement an online vault storing encrypted files

### Understanding

there is three entities: the `client`, the `server` and the `vault`

the server is just a bridge between the two, when a client is authenticated it can ask for encrypted file, that will have to be decrypted by itself.

is the password a master key, capable of answering challenges, decrypting the file list and deriving each key for each file ?

### Checkmarks

- [ ] client side
  - [ ] client has only one password
  - [ ] client can answer challenges
  - [ ] client can decrypt filenames list
  - [ ] client can ask for a file
  - [ ] client can decrypt file
- [ ] server side
  - [ ] server can ask challenges
  - [ ] server can fetch encrypted filename list
  - [ ] server can fetch encrypted file
- [ ] vault side
  - [ ] vault stores encrypted filenames
  - [ ] vault stores encrypted files

### Possible Bonuses (Boni ?)

- server can work with multiple user
  - server cant distinguish between user file (aka which file is to whomst)
- file sharing among user ???
  - what ???
- multi factor auth
  - just cc from sec
- use TPM to secure secrets
- and more

### Report

can be found in doc/

### Notes

Everything will be simulated (database, server)