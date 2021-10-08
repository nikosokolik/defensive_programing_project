#!/bin/python
import pathlib
from server import Server


def get_port() -> int:
    port_file = pathlib.Path(__file__).parent.joinpath("port.info")
    if not port_file.exists():
        print("Port file not found!")
        exit(-1)
    try:
        return int(port_file.read_text().splitlines()[0].strip())
    except ValueError:
        print(f"Could not load port file {port_file}")
        exit(-1)


def main() -> None:
    port = get_port()
    with Server(("0.0.0.0", port)) as serv:
        try:
            serv.serve_forever()
        except:
            print("Shutting server down!")


if __name__ == "__main__":
    main()
