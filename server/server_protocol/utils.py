from typing import List, Callable


class ProtocolError(Exception):
    ...


def generate_pack(argument_list: List[str]) -> Callable[..., bytes]:
    """
    A decorator for generating the pack function. Meant to be called directly and not for decoration.
    Uses the argument_list to unpack the value of self.format into the argument list
    :param argument_list:
    :return:
    """

    def pack(class_instance):
        args = [getattr(class_instance, arg) for arg in argument_list]
        return class_instance.format.pack(*args)

    return pack
