"""This is a cfn-giam main program."""
import requests
import json
import os
import argparse
import glob
import re
import boto3
import logging
from pathlib import Path
from cfngiam import unsupported
from cfngiam import version
import uuid
from datetime import date, datetime
import numpy as np

logger = logging.getLogger(__name__)

def json_serial(obj):
    """convert json datetime serial"""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError ("Type %s not serializable" % type(obj))

def parse_cfn(content: str):
    """pick up AWS resouce type"""
    try:
        pattern = r'\w+::\w+::\w+'
        typename_list = re.findall(pattern, content)
        interface_str = 'AWS::CloudFormation::Interface'
        if interface_str in typename_list:
            typename_list.remove(interface_str)
    except Exception as e:
        logging.error(e)
        raise ValueError('Missing AWS Resouce type')
    only_typename_list = list(set(typename_list))
    return only_typename_list

def load_cfn(filepath: str):
    """load to Cloudformation file"""
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
    """create to IAM policy"""
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
        except Exception as e:
            logging.error(e)
            logging.warning('Fail to request aws cloudformation describe_type: ' + typename)
            continue
        try:
            schema = json.loads(response['Schema'])
            if 'handlers' in schema:
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
            else:
                try:
                    statements = unsupported.load_statements(typename)
                    index = 0
                    for v in statements:
                        v['Sid'] = typename.replace(":", "") + "Access" + str(index)
                        index = index + 1
                    result['Statement'].extend(statements)
                except Exception as e:
                    logging.warning(e)
                    logging.warning('Not supported resouce type: ' + typename)

        except Exception as e:
            logging.error(e)
            logging.warning('Missing schema in ' + typename)
            continue
    return result

def generate_filepath(basefilepath: str, input_path: str, output_folder: str):
    """generate to filepath"""
    try:
        p_basefilepath = Path(basefilepath)
        p_input_path = Path(input_path)
        p_output_path = Path(output_folder)
        if p_basefilepath.parent != p_input_path.parent:
            generatepath = str(p_basefilepath.parent) \
                .replace(str(p_input_path.parent), str(p_output_path))
            r = str(Path(generatepath).joinpath(p_basefilepath.name))
        else:
            r = p_basefilepath.name
        return os.path.join(
            output_folder,
            r.replace('.yaml', '.json') \
            .replace('.yml', '.json') \
            .replace('.template', '.json'))
    except Exception as e:
        logging.error(e)
        raise ValueError(
            'Fail to replace filepath.\nInput path: ' \
                + input_path + '\nOutput path: ' + output_folder)

def output_IAMPolicy(filepath: str, iampolicy_dict: dict):
    """output to IAM policy"""
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        iampolicy_size = len(json.dumps(iampolicy_dict, indent=2, default=json_serial))
        if iampolicy_size > 4000:
            statements = np.array_split(iampolicy_dict['Statement'], int(iampolicy_size / 3000))
            index = 0
            for s in statements:
                d = {
                    "Version": "2012-10-17",
                    "Statement": s.tolist()
                }
                filepath_index = filepath.replace('.json', '{}.json'.format(index))
                with open(filepath_index, 'w', encoding="utf-8") as f:
                    json.dump(d, f, indent=2, default=json_serial)
                index = index + 1
        else:
            with open(filepath, 'w', encoding="utf-8") as f:
                json.dump(iampolicy_dict, f, indent=2, default=json_serial)
    except Exception as e:
        logging.error(e)
        raise ValueError('Fail to output file: ' + filepath)

def create_master_policy(output_folder: str):
    """create to master IAM policy"""
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
        except Exception as e:
            logging.error(e)
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
        except Exception as e:
            logging.error(e)
            logging.warning('Not supported file for IAM policy: ' + filepath)

    try:
        outputpath = os.path.join(output_folder, 'MasterPolicy.json')
        iampolicy_size = len(json.dumps(result, indent=2, default=json_serial))
        if iampolicy_size > 4000:
            statements = np.array_split(result['Statement'], int(iampolicy_size / 3000))
            index = 0
            for s in statements:
                d = {
                    "Version": "2012-10-17",
                    "Statement": s.tolist()
                }
                filepath_index = outputpath.replace('.json', '{}.json'.format(index))
                with open(filepath_index, 'w', encoding="utf-8") as f:
                    json.dump(d, f, indent=2, default=json_serial)
                index = index + 1
        else:
            with open(outputpath, 'w', encoding="utf-8") as f:
                json.dump(result, f, indent=2, default=json_serial)
    except Exception as e:
        logging.error(e)
        raise ValueError('Fail to output file: ' + os.path.join(output_folder, 'MasterPolicy.json'))
    return outputpath, result

def convert_cfn_to_iampolicy(args, filepath: str):
    """convert to IAM policy"""
    target_type_list = load_cfn(filepath)
    logger.info(target_type_list)
    iampolicy_dict = create_IAMPolicy(target_type_list)
    logger.info(iampolicy_dict)
    output_filepath = generate_filepath(filepath, args.input_path, args.output_folder)
    logger.info(output_filepath)
    output_IAMPolicy(output_filepath, iampolicy_dict)
    return output_filepath, iampolicy_dict

def convert_cfn_to_iampolicy_from_web(args):
    """cfn-giam input url"""
    try:
        content = requests.get(args.input_path)
    except Exception as e:
        logging.error(e)
        raise ValueError('Fail to access url: ' + args.input_path)
    logger.info(content.text)
    target_type_list = parse_cfn(content.text)
    logger.info(target_type_list)
    iampolicy_dict = create_IAMPolicy(target_type_list)
    logger.info(iampolicy_dict)
    output_filepath = generate_filepath(args.input_path, args.input_path, args.output_folder)
    logger.info(output_filepath)
    output_IAMPolicy(output_filepath, iampolicy_dict)
    return output_filepath, iampolicy_dict

def create_IAM_Policy(policy_name: str, target_name: str, policy_document: dict):
    """ create IAM Policy """
    
    createname = policy_name + '_' + str(uuid.uuid4())
    policy_document["Version"] = "2012-10-17"
    policy_str = json.dumps(policy_document, default=json_serial)
    iampolicy_size = len(policy_str)
    client = boto3.client('iam')
    result = []
    try:
        if iampolicy_size > 4000:
            statements = np.array_split(policy_document['Statement'], int(iampolicy_size / 3000))
            index = 0
            for s in statements:
                d = {
                    "Version": "2012-10-17",
                    "Statement": s.tolist()
                }
                response = client.create_policy(
                    PolicyName=createname,
                    PolicyDocument=json.dumps(d, default=json_serial),
                    Description='Created IAM Policy from {}_{}.'.format(target_name, index),
                    Tags=[
                        {
                            'Key': 'Name',
                            'Value': createname + '_' + str(index)
                        },
                    ]
                )
                result.append(response['Policy']['Arn'])
                index = index + 1
        else:
            response = client.create_policy(
                PolicyName=createname,
                PolicyDocument=policy_str,
                Description='Created IAM Policy from {}.'.format(target_name),
                Tags=[
                    {
                        'Key': 'Name',
                        'Value': createname
                    },
                ]
            )
            result.append(response['Policy']['Arn'])
    except Exception as e:
        logging.error(e)
        raise ValueError('Fail to create IAM Policy: ' + policy_str)
    logging.info(json.dumps(response, default=json_serial))
    return result

def create_IAM_Role(role_name: str, target_name: str, policy_arn_list: list):
    """ create IAM Role """
    
    createname = role_name + '_' + str(uuid.uuid4())
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Effect": "Allow",
                "Principal": {
                    "Service": "cloudformation.amazonaws.com"
                }
            }
        ]
    }
    client = boto3.client('iam')
    try:
        response = client.create_role(
            RoleName=createname,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document, default=json_serial),
            Description='Created IAM Role from {}.'.format(target_name),
            MaxSessionDuration=43200,
            Tags=[
                {
                    'Key': 'Name',
                    'Value': createname
                },
            ]
        )
        for policy_arn in policy_arn_list:
            client.attach_role_policy(RoleName=createname, PolicyArn=policy_arn)
    except Exception as e:
        logging.error(e)
        raise ValueError('Fail to create IAM Role: ' + createname)
    logging.info(json.dumps(response, default=json_serial))

def with_input_folder(args):
    """cfn-giam input path"""
    pattern = r"https?://[\w/:%#\$&\?\(\)~\.=\+\-]+"
    output_path = ''
    policy_document = {}
    if re.match(pattern, args.input_path):
        if args.output_folder == None:
            args.output_folder = './'
        output_path, policy_document = convert_cfn_to_iampolicy_from_web(args)
    elif os.path.isdir(args.input_path):
        if args.output_folder == None:
            args.output_folder = Path(args.input_path).parent
        for filepath in glob.glob(os.path.join(args.input_path + "/**/*.*"), recursive=True):
            if os.path.isdir(filepath):
                continue
            convert_cfn_to_iampolicy(args, filepath)
        output_path, policy_document = create_master_policy(args.output_folder)
        logger.info(policy_document)
    else:
        if args.output_folder == None:
            args.output_folder = Path(args.input_path).parent
        output_path, policy_document = convert_cfn_to_iampolicy(args, args.input_path)
    
    if args.policy != None or args.role != None:
        policy_arn_list = create_IAM_Policy(args.policy, output_path, policy_document)
        if args.role != None:
            create_IAM_Role(args.role, output_path, policy_arn_list)

def with_input_list(args):
    """cfn-giam input list"""
    try:
        iampolicy_dict = create_IAMPolicy(args.input_list.split(','))
    except Exception as e:
        logging.error(e)
        raise ValueError('Not supported format: ' + args.input_list)
    logger.info(iampolicy_dict)
    output_path = os.path.join(args.output_folder, 'IAMPolicy.json')
    output_IAMPolicy(output_path, iampolicy_dict)
    
    if args.policy != None:
        create_IAM_Policy(args.policy, output_path, iampolicy_dict)
    if args.role != None:
        create_IAM_Role(args.role, output_path, iampolicy_dict)

def main():
    """cfn-giam main"""
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-i", "--input-path",
        type=str,
        action="store",
        help="Cloudformation file, folder or url path having Cloudformation files. \
            Supported yaml and json. If this path is a folder, it will be detected recursively.",
        dest="input_path"
    )
    parser.add_argument(
        "-l", "--input-resource-type-list",
        type=str,
        action="store",
        help="AWS Resouce type name list of comma-separated strings. e.g. \
            \"AWS::IAM::Role,AWS::VPC::EC2\"",
        dest="input_list"
    )
    parser.add_argument(
        "-o", "--output-folderpath",
        type=str,
        action="store",
        dest="output_folder",
        help="Output IAM policy files root folder.If not specified, it matches the input-path. \
            Moreover, if input-path is not specified, it will be output to the current directory."
    )
    parser.add_argument(
        "-p", "--policy",
        type=str,
        action="store",
        dest="policy",
        help="Set the name of the IAM Policy to be created on AWS."
    )
    parser.add_argument(
        "-r", "--role",
        type=str,
        action="store",
        dest="role",
        help="Set the name of the IAM Role to be created on AWS."
    )
    parser.add_argument(
        "-v", "--version",
        action='version',
        version=version.__version__,
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
        logging.basicConfig(level=logging.INFO, format='%(message)s')
        logger.info('Set detail log level.')
    else:
        logging.basicConfig(level=logging.WARNING, format='%(message)s')

    if args.input_path == None and args.input_list == None:
        logger.error("Missing input filename and list. Either is required.")
        return
    elif args.input_path != None and args.input_list != None:
        logger.error("Conflicting input filename and list. Do only one.")
        return

    if args.output_folder != None:
        logger.info('Output folder: ' + args.output_folder)

    logger.info('Start to create IAM Policy file')
    if args.input_path != None:
        logger.info('Input path: ' + args.input_path)
        try:
            with_input_folder(args)
        except Exception as e:
            logging.error(e)
            logger.error('Fail to generate: ' + args.input_path)
            return
    else:
        logger.info('Input list: ' + args.input_list)
        try:
            args.output_folder = './'
            with_input_list(args)
        except Exception as e:
            logging.error(e)
            logger.error('Fail to generate: ' + args.input_list)
            return

    logger.info('Successfully to create IAM Policy files')

if __name__ == "__main__":
    # execute only if run as a script
    main()
