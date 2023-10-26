import json
import os

"""
A module to manage the configuration of the cameras
"""

def read_config(filename):
    try:
        with open(filename, "r") as file:
            data = json.load(file)
        return data
    except FileNotFoundError:
        print(f"{filename} does not exist.")
    except Exception as e:
        print(f"An error occurred while reading from '{filename}': {str(e)}.")
        return None

def write_config(data, filename):
    try:
        with open(filename, "w") as file:
            json.dump(data, file, indent=4)
        print(f"Config has been succesfully written to {filename}.")
    except Exception as e:
        print(f"An error occurred while writing {filename}.")