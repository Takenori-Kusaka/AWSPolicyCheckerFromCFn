import requests
import json
import os
import argparse
import glob
import re
import boto3
import logging
from pathlib import Path
try:
    from .version import __version__
except:
    from version import __version__

logger = logging.getLogger(__name__)

def parse_cfn(content: str):
    try:
        pattern = '\w+::\w+::\w+'
        typename_list = re.findall(pattern, content)
    except:
        raise ValueError('Missing AWS Resouce type')
    only_typename_list = list(set(typename_list))
    return only_typename_list

def load_cfn(filepath: str):
    try:
        result = []
        with open(filepath, encoding="utf-8") as f:
            content = f.read()
            result = parse_cfn(content)
        return result
    except Exception as e:
        logging.error(e)
        raise ValueError('Fail to access file')

def create_IAMPolicy(target_type_list: list):
    result = {
        "Version": "2012-10-17",
        "Statement": []
    }
    client = boto3.client('cloudformation')
    for typename in target_type_list:
        try:
            response = client.describe_type(
                Type='RESOURCE',
                TypeName=typename
            )
        except:
            logging.warning('Fail to request aws cloudformation describe_type: ' + typename)
            continue
        try:
            schema = json.loads(response['Schema'])
            handler = schema['handlers']
            actions = []
            for k, v in handler.items():
                if k == 'create':
                    actions.extend(v['permissions'])
                if k == 'update':
                    actions.extend(v['permissions'])
                elif k == 'delete':
                    actions.extend(v['permissions'])

            statement = {
                "Sid": typename.replace(":", "") + "Access",
                "Effect": "Allow",
                "Action": actions,
                "Resource": "*"
            }
            result['Statement'].append(statement)
        except:
            logging.warning('Missing schema in ' + typename)
            continue
    return result

def generate_filepath(basefilepath: str, input_path: str, output_folder: str):
    try:
        p_basefilepath = Path(basefilepath)
        p_input_path = Path(input_path)
        p_output_path = Path(output_folder)
        if p_basefilepath.parent != p_input_path.parent:
            generatepath = str(p_basefilepath.parent).replace(str(p_input_path.parent), str(p_output_path))
            r = str(Path(generatepath).joinpath(p_basefilepath.name))
        else:
            r = p_basefilepath.name
        return os.path.join(output_folder, r.replace('.yaml', '.json').replace('.yml', '.json').replace('.template', '.json'))
    except:
        raise ValueError('Fail to replace filepath.\nInput path: ' + input_path + '\nOutput path: ' + output_folder)

def output_IAMPolicy(filepath: str, iampolicy_dict: dict):
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding="utf-8") as f:
            json.dump(iampolicy_dict, f, indent=2)
    except:
        raise ValueError('Fail to output file: ' + filepath)

def create_master_policy(output_folder: str):
    result = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CloudformationFullAccess",
                "Effect": "Allow",
                "Action": [
                    "cloudformation:*"
                ],
                "Resource": "*"
            }
        ]
    }
    for filepath in glob.glob(os.path.join(output_folder + "/**/*.json"), recursive=True):
        policy_dict = {}
        try:
            with open(filepath, encoding="utf-8") as f:
                json_str = f.read()
                policy_dict = json.loads(json_str)
        except:
            logging.warning('Fail to access file: ' + filepath)

        try:
            for ps in policy_dict['Statement']:
                exists = False
                for rs in result['Statement']:
                    if ps['Sid'] == rs['Sid']:
                        exists = True
                        break
                if exists == False:
                    result['Statement'].append(ps)
        except:
            logging.warning('Not supported file for IAM policy: ' + filepath)

    try:
        with open(os.path.join(output_folder, 'MasterPolicy.json'), 'w', encoding="utf-8") as f:
            json.dump(result, f, indent=2)
    except:
        raise ValueError('Fail to output file: ' + os.path.join(output_folder, 'MasterPolicy.json'))
    return result

def convert_cfn_to_iampolicy(args, filepath: str):
    target_type_list = load_cfn(filepath)
    logger.info(target_type_list)
    iampolicy_dict = create_IAMPolicy(target_type_list)
    logger.info(iampolicy_dict)
    output_filepath = generate_filepath(filepath, args.input_path, args.output_folder)
    logger.info(output_filepath)
    output_IAMPolicy(output_filepath, iampolicy_dict)

def convert_cfn_to_iampolicy_from_web(args):
    try:
        content = requests.get(args.input_path)
    except:
        raise ValueError('Fail to access url: ' + args.input_path)
    target_type_list = parse_cfn(content.text)
    logger.info(target_type_list)
    iampolicy_dict = create_IAMPolicy(target_type_list)
    logger.info(iampolicy_dict)
    output_filepath = generate_filepath(args.input_path, args.input_path, args.output_folder)
    logger.info(output_filepath)
    output_IAMPolicy(output_filepath, iampolicy_dict)

def with_input_folder(args):

    pattern = "https?://[\w/:%#\$&\?\(\)~\.=\+\-]+"
    if re.match(pattern, args.input_path):
        if args.output_folder != None:
            args.output_folder = './'
        convert_cfn_to_iampolicy_from_web(args)
    elif os.path.isdir(args.input_path):
        if args.output_folder != None:
           args.output_folder = Path(args.input_path).parent
        for filepath in glob.glob(os.path.join(args.input_path + "/**/*.*"), recursive=True):
            if os.path.isdir(filepath):
                continue
            convert_cfn_to_iampolicy(args, filepath)
        master_policy = create_master_policy(args.output_folder)
        logger.info(master_policy)
    else:
        if args.output_folder != None:
            args.output_folder = Path(args.input_path).parent
        convert_cfn_to_iampolicy(args, args.input_path)

def with_input_list(args):
    try:
        iampolicy_dict = create_IAMPolicy(args.input_list.split(','))
    except:
        raise ValueError('Not supported format: ' + args.input_list)
    logger.info(iampolicy_dict)
    output_IAMPolicy(os.path.join(args.output_folder, 'IAMPolicy.json'), iampolicy_dict)

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-i", "--input-path",
        type=str,
        action="store",
        help="Cloudformation file, folder or url path having Cloudformation files. Supported yaml and json. If this path is a folder, it will be detected recursively.",
        dest="input_path"
    )
    parser.add_argument(
        "-l", "--input-resource-type-list",
        type=str,
        action="store",
        help="AWS Resouce type name list of comma-separated strings. e.g. \"AWS::IAM::Role,AWS::VPC::EC2\"",
        dest="input_list"
    )
    parser.add_argument(
        "-o", "--output-folderpath",
        type=str,
        action="store",
        dest="output_folder",
        help="Output IAM policy files root folder.If not specified, it matches the input-path. Moreover, if input-path is not specified, it will be output to the current directory."
    )
    parser.add_argument(
        "-v", "--version",
        action='version',
        version=__version__,
        help="Show version information and quit."
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

    logger.info('Input path: ' + args.input_path)
    logger.info('Input list: ' + args.input_list)
    logger.info('Output folder: ' + args.output_folder)

    if args.input_path == None and args.input_list == None:
        logger.error("Missing input filename and list. Either is required.")
    elif args.input_path != None and args.input_list != None:
        logger.error("Conflicting input filename and list. Do only one.")
    
    logger.info('Start to create IAM Policy file')
    if args.input_path != None:
        try:
            with_input_folder(args)
        except:
            logger.error('Fail to generate: ' + args.input_path)
            return
    else:
        try:
            args.output_folder = './'
            with_input_list(args)
        except:
            logger.error('Fail to generate: ' + args.input_list)
            return

    logger.info('Successfully to create IAM Policy files')

if __name__ == "__main__":
    # execute only if run as a script
    main()