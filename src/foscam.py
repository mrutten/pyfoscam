from libconfig.config import read_config
from libpyfoscam import FoscamCamera
from os import path
from time import sleep

# Constants
CAMERAS = "cameras.json"


def main():
    try:
        if path.exists(f"{CAMERAS}"):
            data = read_config(f"{CAMERAS}")
            cameras = {}
            for key, values in data.items():
                cameras[key] = FoscamCamera(
                    values["host"], values["port"], values["login"], values["password"]
                )
        else:
            print(f"{CAMERAS} does not exist.")
    except FileNotFoundError:
        print(f"Could not read {file}.")

    print(cameras["foscam1"].get_pppoe_config())


if __name__ == "__main__":
    main()
