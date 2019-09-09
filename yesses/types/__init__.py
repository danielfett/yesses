import collections

class Domain:
    domain: str

    def __str__(self):
        return self.domain

class URL:
    url: str

    def __str__(self):
        return self.url

class IP:
    ip: str

    def __str__(self):
        return self.ip

        

class Error:
    error: str

    def __str__(self):
        return self.error

class Errors:
    errors: list

    def __str__(self):
        return ', '.join(self.errors)

class YType(collections.Mapping):
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __getitem__(self, *args):
        return self.__dict__.__getitem__(*args)

    def __iter__(self, *args):
        return self.__dict__.__iter__(*args)

    def __len__(self, *args):
        return self.__dict__.__len__(*args)
            
    def items(self):
        return self.__dict__.items()
