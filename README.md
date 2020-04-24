# Needham Schroeder Secure Communication Network

Suppose Alice and Bob want to authenticate each other and communicate securely with each other.
With the help of a trusted server, the Needham-Schroeder protocol helps them establish a shared session key which they use to encrypt further messages.

This implementation includes fixes to the original protocol to prevent replay attacks using nonces and uses AES encryption instead of original protocol's DES method of encryption.

The use of brackets {} indicates encrypted message, followed by the key used in encryption.

kAS = Alice's server key

kBS = Bob's server key

## Implemented Needham-Schroeder-Protocol
(A -> S) : A, B, Na (nonce), Nb (nonce) 

(S -> A) : {session key, B, Na}kAS, {session key, A, Nb}kBS

(A -> B) : {session key, A, Nb}kBS

(B -> A) : B, Nb

## Running the Code
Begin by running two client consoles:<br>
``java client.Client``

Entering a clientname:
``A`` or ``B``

Then run the server:
``java server.Server``

Logs will show transmitted messages, decrypted messages and established keys.
Opting out of logs will only show transmitted messages (essentially the adversary view).
Choose whether or not to include logs.
``True`` or ``False``

Once a session key is established, Alice and Bob can begin secure communication by encrypting messages.
A new initialization vector is generated for each round of messaging.

Note: for every round of messages, Alice must enter a message first, then Bob.

Example:<br>
Alice's console:<br>
``Round 1
  Enter message to send securely: <Alice's message>``<br>
Bob's console:<br>
``Round 1
  Enter message to send securely: <Bob's message>``  

