# author: Asif Azad
# Date: 2020-12-26
# About: Elliptic Curve Diffie-Hellman Key Exchange; ECDHCipher.py

import random
from sympy import isprime

SECURITY_LEVELS = [128, 192, 256]

class Point:
    def __init__(self, x: int, y: int)-> None:
        self.x = x
        self.y = y
    
    def __str__(self)-> str:
        return f"({self.x}, {self.y})"    


class ECDHCipher:
    def __init__(self, _security_level: int = 0, _curve: object = None)-> None:
        if(_curve is None):
            assert _security_level < len(SECURITY_LEVELS), "Invalid security level"
            _curve = self.generate_parameters(_security_level)
        else:
            # assert whether the curve has all the required parameters
            assert 'a' in _curve and 'b' in _curve and 'p' in _curve and 'k' in _curve and 'gx' in _curve and 'gy' in _curve, "Invalid curve"
        self.a = _curve['a']
        self.b = _curve['b']
        self.p = _curve['p']
        self.k = _curve['k']
        self.base_point = Point(_curve['gx'], _curve['gy'])        
    
    def get_parameters(self)->dict:
        return {
            "a": self.a,
            "b": self.b,
            "p": self.p,
            "k": self.k,
            "gx": self.base_point.x,
            "gy": self.base_point.y
        }
    
    def generate_parameters(self, _security_level: int = 0)-> dict:
        k = SECURITY_LEVELS[_security_level]
        p = self.generate_kbit_prime(k)
        while True:
            a = random.randint(1, p-1)
            gx = random.randint(1, p-1)
            gy = random.randint(1, p-1)
            b = (gy*gy - gx*gx*gx - a*gx) % p
            if (4*a*a*a + 27*b*b) % p != 0:
                return {
                    "a": a,
                    "b": b,
                    "p": p,
                    "k": k,
                    "gx": gx,
                    "gy": gy
                }

    def generate_kbit_prime(self, k: int)-> int:
        while True:
            kbit_prime = random.randint(2**(k-1), 2**k - 1)
            if isprime(kbit_prime):
                return kbit_prime
    
    def show_curve(self)-> None:
        print(f"y^2 = x^3 + {self.a}x + {self.b} mod {self.p}\nG = {self.base_point}")

    def add_points(self, p: Point = None, q: Point = None)-> Point:
        if p is None:
            p = self.base_point
        if q is None:
            q = self.base_point
        if p.x == q.x and p.y == q.y:
            s = ((3 * p.x * p.x + self.a) * pow(2 * p.y, -1, self.p)) % self.p
        else:
            s = ((q.y - p.y) * pow(q.x - p.x, -1, self.p)) % self.p
        x = (s * s - p.x - q.x + self.p) % self.p
        y = (s * (p.x - x) - p.y + self.p) % self.p
        return Point(x, y) 
    
    def multiply_point(self, n: int, p: Point = None)-> Point:
        if p is None:
            p = self.base_point
        if n == 1:
            return p
        if n % 2 == 0:
            return self.multiply_point(n//2, self.add_points(p, p))
        else:
            return self.add_points(p, self.multiply_point(n-1, p))
    
    def generate_private_key(self)-> int:
        return random.randint(1, 2**self.k - 1) % self.p

