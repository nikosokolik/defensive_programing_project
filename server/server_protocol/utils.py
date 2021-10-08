from typing import List, Callable, Any


class ProtocolError(Exception):
    ...


def generate_pack(class_instance: Any, argument_list: List[str]) -> bytes:
    if not hasattr(class_instance, "format"):
        return b""
    args = [getattr(class_instance, arg) for arg in argument_list]
    return class_instance.format.pack(*args)
