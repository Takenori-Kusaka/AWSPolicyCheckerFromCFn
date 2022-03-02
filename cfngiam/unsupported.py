import json
import logging
import argparse
import pkg_resources

logger = logging.getLogger(__name__)

def load_statements(resouce_type: str):
    filename = resouce_type.replace(':', '') + '.json'
    json_str = pkg_resources.resource_string('cfngiam', 'unsupported/' + filename).decode()
    json_policy = json.load(json_str)
    return json_policy['Statement']

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-r", "--resouce-type",
        type=str,
        action="store",
        help="Cloudformation resouce type",
        dest="resouce_type"
    )
    parser.add_argument(
        "-V", "--verbose",
        action='store_true',
        dest="detail",
        help="give more detailed output"
    )
    args = parser.parse_args()

    if args.detail:
        logger.setLevel(logging.INFO)
        logger.info('Set detail log level.')
    else:
        logger.setLevel(logging.WARNING)

    print(load_statements(args.resouce_type))

if __name__ == "__main__":
    # execute only if run as a script
    main()
