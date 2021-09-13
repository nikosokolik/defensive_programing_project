import pathlib
from server import Server


def get_port() -> int:
    port_file = pathlib.Path(__file__).parent.joinpath("port.info")
    if not port_file.exists():
        print("Port file not found!")
        exit(-1)
    return int(port_file.read_text().splitlines()[0])


def main() -> None:
    port = get_port()
    with Server(("0.0.0.0", port)) as serv:
        serv.serve_forever()


if __name__ == "__main__":
    main()
