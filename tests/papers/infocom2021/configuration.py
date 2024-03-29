from common.stereotype_tags import StereotypeTags, DeviceClass

from ipaddress import IPv6Address

hostname_to_ips = {
    "wsn1": IPv6Address("fd00::1"),
    "wsn2": IPv6Address("fd00::212:4b00:14d5:2bd6"),
    "wsn3": IPv6Address("fd00::212:4b00:14d5:2ddb"),
    "wsn4": IPv6Address("fd00::212:4b00:14d5:2be6"),
    "wsn5": IPv6Address("fd00::212:4b00:14b5:da27"),
    "wsn6": IPv6Address("fd00::212:4b00:14d5:2f05"),
}

root_node = "wsn1"

device_stereotypes = {
    "wsn1": StereotypeTags(device_class=DeviceClass.SERVER),         # Root
    "wsn2": StereotypeTags(device_class=DeviceClass.RASPBERRY_PI),   # Edge
    "wsn3": StereotypeTags(device_class=DeviceClass.IOT_MEDIUM),     # IoT
    "wsn4": StereotypeTags(device_class=DeviceClass.IOT_MEDIUM),     # IoT
    "wsn5": StereotypeTags(device_class=DeviceClass.IOT_MEDIUM),     # IoT
    "wsn6": StereotypeTags(device_class=DeviceClass.RASPBERRY_PI),   # Edge
}

hostname_to_names = {
    "wsn1": "root",
    "wsn2": "rr2",
    "wsn3": "wsn3",
    "wsn4": "wsn4",
    "wsn5": "wsn5",
    "wsn6": "rr6",
}
