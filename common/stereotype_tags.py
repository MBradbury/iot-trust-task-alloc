from enum import IntEnum
from dataclasses import dataclass

class DeviceClass(IntEnum):
    RASPBERRY_PI = 1
    PHONE = 2
    LAPTOP = 3
    DESKTOP = 4
    SERVER = 5

    def encode(self):
        return int(self)

    def cname(self):
        return "DEVICE_CLASS_" + self.name

@dataclass
class StereotypeTags:
    device_class: DeviceClass

    def __post_init__(self):
        super().__setattr__("device_class", DeviceClass(self.device_class))

    def encode(self):
        return [
            self.device_class.encode()
        ]
