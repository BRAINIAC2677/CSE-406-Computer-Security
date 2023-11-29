import random

NIST_STANDARD_CURVES = [
    {
        "name": "P-128",
        "k": 128,
        "a": -3,
        "b": 0x000E0D4D696E6768756151750CC03A4473D03679,
        "p": 2**128 - 159,
        "gx": 0x161FF7528B899B2D0C28607CA52C5B86,
        "gy": 0xCF5AC8395BAFEB13C02DA292DDED7A83
    },
    {
        "name": "P-192",
        "k": 192,
        "a": -3,
        "b": 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1,
        "p": 2**192 - 2**64 - 1,
        "gx": 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,
        "gy": 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811,
    },
    {
        "name": "P-256",
        "k": 256,
        "a": -3,
        "b": 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        "p": 2**256 - 2**224 + 2**192 + 2**96 - 1,
        "gx" : 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        "gy" : 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    }
]


class Point:
    def __init__(self, x: int, y: int)-> None:
        self.x = x
        self.y = y
    
    def __str__(self)-> str:
        return f"({self.x}, {self.y})"    


class ECDHCipher:
    def __init__(self, _security_level: int = 0, _curve: object = None)-> None:
        if(_curve is None):
            assert _security_level < len(NIST_STANDARD_CURVES), "Invalid security level"
            _curve = NIST_STANDARD_CURVES[_security_level]
        else:
            # assert whether the curve has all the required parameters
            assert 'a' in _curve and 'b' in _curve and 'p' in _curve and 'k' in _curve and 'gx' in _curve and 'gy' in _curve, "Invalid curve"
        self.a = _curve['a']
        self.b = _curve['b']
        self.p = _curve['p']
        self.k = _curve['k']
        self.base_point = Point(_curve['gx'], _curve['gy'])        

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

