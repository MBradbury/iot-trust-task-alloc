from enum import IntEnum
from dataclasses import dataclass

class DeviceClass(IntEnum):
    RASPBERRY_PI = 1
    PHONE = 2
    LAPTOP = 3
    DESKTOP = 4
    SERVER = 5

    IOT_LOW = 6
    IOT_MEDIUM = 7
    IOT_HIGH = 8

    def encode(self):
        return int(self)

    def cname(self):
        return "DEVICE_CLASS_" + self.name

    def __str__(self):
        return self.name

    @staticmethod
    def from_string(s):
        try:
            return DeviceClass[s]
        except KeyError:
            raise ValueError()

@dataclass
class StereotypeTags:
    device_class: DeviceClass

    def __post_init__(self):
        super().__setattr__("device_class", DeviceClass(self.device_class))

    def encode(self):
        return [
            self.device_class.encode()
        ]

    @staticmethod
    def decode(data: bytes):
        return StereotypeTags(
            device_class=DeviceClass(data[0])
        )
