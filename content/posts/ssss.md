---
title: "SSSS"
date: 2025-08-18
draft: false
tags: ["cryptography", "sekaictf2025"]
---

### Challenge Description 
    Shamir SendS the Secret to everyone
    Author : Utaha
    Points : 100 pts

### Source code 
```python
import random, os


p = 2 ** 256 - 189

FLAG = os.getenv("FLAG", "SEKAI{}")


def challenge(secret):

  t = int(input())

  assert 20 <= t <= 50, "Number of parties not in range"


  f = gen(t, secret)


  for i in range(t):

    x = int(input())

    assert 0 < x < p, "Bad input"

    print(poly_eval(f, x))


  if int(input()) == secret:

    print(FLAG)

    exit(0)

  else:

    print(":<")


def gen(degree, secret):

  poly = [random.randrange(0, p) for _ in range(degree + 1)]

  index = random.randint(0, degree)


  poly[index] = secret

  return poly


def poly_eval(f, x):

  return sum(c * pow(x, i, p) for i, c in enumerate(f)) % p


if __name__ == "__main__":

  secret = random.randrange(0, p)

  for _ in range(2):

    challenge(secret)
```

### How Shamir's secret sharing scheme (SSS) works ?

- Let's say S is the secret that we wish to share.

- It is divided into N parts: S1, S2, S3, ...., Sn.

- After dividing it, a number K is chosen by the user in order to decrypt the parts and find the original secret.

- It is chosen in such a way that if we know less than K parts, then we will not be able to find the secret S (i.e.) the secret S can not be reconstructed with (K - 1) parts or fewer.

- If we know K or more parts from S1, S2, S3, ...., Sn, then we can reconstructe our secret S easily. This is conventionally called (K, N) threshold scheme.

### Solution 

#### Challenge description
For a polynomial of degree `d` we need `d+1` points in order to reconstruct the polynomial and retrieve the secret

Here in the challenge the server generates two random polynomials over $\mathbb{F}_p$ with p = $2^{256}$ - 189 , but in each polynomial , one randomly chosen coefficient is set to the same secret , so this isn't standart , as in the standard shamir's secret sharing scheme the secret is the free coefficient.

The secret is the unique intersection of the coefficient sets of both polynomials.

#### The problem

Normally , reconstructing a polynomial of degree `d` needs `d+1` queries. Here d is at most 50 , so 51 queries in that case for example  would be needed but we are allowed to only d queries.

#### The exploit

If we observe that `(p-1) mod 29 = 0` , we deduce that there exists an element `g` of order 29 in $\mathbb{F}_p^*$. In this case , $x^{t}$ = $x^{29}$ = 1 , so the constent term overlaps with the  `t`-th term

Using Sage’s `lagrange_polynomial` over the subgroup points, we recover the coefficients of this polynomial.

#### Solver
```python
from os import environ
environ['TERM'] = 'xterm'
from sage.all import *
from pwn import *




p = 2 ** 256 - 189
R = PolynomialRing(GF(p), 'x')
io = remote('ssss.chals.sekai.team', 1337 , ssl=True)


def sample_collect():

    io.sendline(str(29).encode())

    while True:
    
        # find a generator g of order 29
        g = randint(1, p)

        g = pow(g, (p-1)//29, p)

        if g != 1:

            break

    shares = []

    for i in range(29):

        x0 = pow(g, i, p)
        io.sendline(str(x0).encode())
        y0 = int(io.recvline().strip())
        shares.append((x0, y0))

    return R.lagrange_polynomial(shares).coefficients()


set1 = sample_collect()
# just a dummy value for the first challenge
io.sendline(b'1')
io.recvline()
set2 = sample_collect()


for secret in set(set1) & set(set2):
    io.sendline(str(secret).encode())
    print(io.recvline().decode())
```

Flag : `SEKAI{https://youtu.be/XGxIE1hr0w4}`