import argparse
import json
import pathlib


def update_content(mbc_path: pathlib.Path) -> None:
    """
    This script is meant to locally modify the STIX2 MBC content into
    something the attack-navigator can support. Since MBC does not give
    details platforms, the field `x_mitre_platform` is not provided.
    """
    with mbc_path.open("r", encoding="utf-8") as f:
        mbc_objects = json.load(f)

    for mbc_object in mbc_objects["objects"]:
        if mbc_object["type"] == "attack-pattern":
            mbc_object["x_mitre_platforms"] = ["N/A"]

    with open("mbc-attack-nav-modified.json", "w", encoding="utf-8") as f:
        json.dump(mbc_objects, f)


def get_argparse() -> argparse.ArgumentParser:
    """Defines argument parser for this script"""
    parser = argparse.ArgumentParser(description="Modify MBC content to be compatible with the ATT&CK Navigator")
    parser.add_argument("--mbc-content-location",
                        type=lambda path: pathlib.Path(path),
                        default=pathlib.Path("..", "mbc", "mbc.json"))
    return parser


def main():
    arg_parser = get_argparse()
    args = arg_parser.parse_args()
    update_content(args.mbc_content_location)


if __name__ == "__main__":
    main()
