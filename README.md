# IDOR Lab

An intentionally vulnerable Express.js API demonstrating **IDOR
(Insecure Direct Object Reference)**, also known as Broken Object
Level Authorization — currently **#1 on the OWASP API Security Top
10 (2023)**.

## What's vulnerable

`GET /api/user/:id` checks that the caller is *logged in*, but never
checks that the `:id` being requested actually belongs to the caller.
Any authenticated user can read any other user's data just by
changing the number in the URL.

`GET /api/secure/user/:id` is the fixed version: it checks that the
requested id matches the token owner's own id.

## Setup (Windows)

```
npm install
npm start
```

Server runs on http://localhost:3000. Open it in a browser to try
the login + profile demo, or test with the accounts below.

Test accounts: `alice/alice123`, `bob/bob123`, `carol/carol123`

## Attack (Kali Linux)

```
git clone <your-repo-url>
cd idor-lab
npm install
npm start
```

In another terminal:

```
chmod +x attack.sh
./attack.sh <server-ip> 3000
```

The script logs in as alice, then uses alice's own token to pull
bob's and carol's private data from the vulnerable endpoint, and
shows the same attack correctly blocked (403) on the fixed endpoint.

## Fix applied

Object-level authorization check: compare the authenticated user's
id (from their session/token) against the id in the request path,
and reject the request if they don't match.
