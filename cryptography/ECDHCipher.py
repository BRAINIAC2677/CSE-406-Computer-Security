
class Point:
    def __init__(self, x: int, y: int)-> None:
        self.x = x
        self.y = y

    def __str__(self)-> str:
        return f"({self.x}, {self.y})"    


class ECDHCipher:
    def __init__(self, a: int, b: int, p: int, x: int, y: int)-> None:
        self.a = a
        self.b = b
        self.p = p
        self.base_point = Point(x, y)

    def add_points(self, p: Point = None, q: Point = None)-> Point:
        if p is None:
            p = self.base_point
        if q is None:
            q = self.base_point
        if p.x == q.x and p.y == q.y:
            s = ((3 * p.x * p.x + self.a) * pow(2 * p.y, -1, self.p)) % self.p
        else:
            s = ((q.y - p.y) * pow(q.x - p.x, -1, self.p)) % self.p
        x = (s * s - p.x - q.x) % self.p
        y = (s * (p.x - x) - p.y) % self.p
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



