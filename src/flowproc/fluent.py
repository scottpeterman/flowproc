# https://gist.github.com/thinkingserious/d1b06ee12a3613c0dc3b

import sys

from ipaddress import ip_address


class Fluent:
    def __init__(self, cache=None):
        self._cache = cache or []

    # Build the cache, and handle special cases
    def _(self, name):
        # Enables method chaining
        return Fluent(self._cache+[name])

    # Final method call accepting an argument
    def process(self, data):
        for func in self._cache:
            # Cool, yep - just inspect the cache and check if sequence found
            # is allowed consulting a state transition table :))
            data = func(data)

    # Reflection to get an object
    def __getattr__(self, name):
        obj = globals()[name]
        return self._(obj)

    # Called with the object is deleted
    def __del__(self):
        print('Deleting', self)


def to_ip(data):
    return ip_address(int(data))


def print_ip(data):
    print(data)
    return(data)


fluent = Fluent()
chain = fluent.to_ip.print_ip
chain.process(sys.argv[1] if len(sys.argv) > 1 else 0)
