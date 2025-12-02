🧪 How to Run This for Your Demo

Save file as:
scripts/mitm-demo.ts

Install ts-node if you don’t have it:

npm install --save-dev ts-node typescript


Run:

npx ts-node scripts/mitm-demo.ts


In your video / report, highlight:

Part 1 – Vulnerable DH (No Signatures)

Show terminal output:

Client & Server derive different secrets

Attacker derives two secrets: one with client, one with server

Attacker decrypts the client’s secret message

Re-encrypts and sends to server

Explain:

“This simulates a DH handshake without signatures. The attacker sits in the middle, establishes one key with the client and another key with the server, and can fully read/modify traffic.”

Part 2 – Signed ECDH (Your Protocol)

Show terminal output:

MITM tampers with the client’s ephemeral key

Signature verification fails on server side

Handshake is aborted

Explain:

“Now when we add identity keys and signatures, the attacker can’t modify the key without invalidating the signature. The server rejects the handshake, so the MITM attack fails.”

🔗 How This Ties Back to Your Project

You can explicitly say in your report:

The insecure demo corresponds to Diffie–Hellman without signatures, which your assignment warns is vulnerable to MITM.

The secure demo mirrors your real key-exchange implementation, where:

Ephemeral key is signed by identity key

Server verifies signature

MITM cannot swap keys without breaking verification

This fulfills the "MITM attack demonstration" requirement from your documents — without breaking your actual app or adding messy temp routes.