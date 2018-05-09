#!/usr/bin/env python3
# encoding: utf-8

"""
getawscreds.py
Created by Raul Cuza on 2017-10-24.
Copyright (c) 2016, Raúl Cuza. All rights reserved.

This script will attempt to be python2 and python3 compatible.
"""

from __future__ import absolute_import, division, print_function

import argparse
import getpass
import json
import logging
import os
import stat
import sys

import hvac

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

LICENSE = """
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

HELP_MESSAGE = """
This script will authenticate you to vault and set
your temporary credentials in ~/.aws/credentials.
"""

VERINFO = '0.1.1'
DEFAULT_PASSWORD_FILE = '~/.vault_pass'
VAULT_ADDR = os.getenv('VAULT_ADDR', None)
VAULT_TOKEN = os.getenv('VAULT_TOKEN', '~/.vault-token')
AWS_CONFIG_FILE = os.getenv('AWS_CONFIG_FILE', '~/.aws/credentials')


def get_password(pwd_file=None):
    """
    Get password from file or command line
    """

    # if password file was passed, try to read it for a password
    # else ask on the command line
    if pwd_file:
        # XXX Add check that file has 0600 mode
        try:
            password = pwd_file.read()
            pwd_file.close()
            if password:
                logging.debug("PASSWORD READ FROM FILE")
            else:
                raise ValueError()
        except ValueError:
            logging.debug("nothing found in password file")
    else:
        password = getpass.getpass('Token (will be hidden): ')

    return password.strip()

def test_mock_data_from_vault():
    """
    Mock of data from vault
    """
    logging.debug('SCRIPT IS SET TO SEND FALSE CREDS')

    result_of_auth_json = """{
    "warnings": "false auth"
}"""
    result_of_read_json = """{
	"request_id": "",
	"lease_id": "devops/creds/superuser/a7a8fea7-7933-bb35-fcf9-e76484501e07",
	"lease_duration": 28800,
	"renewable": true,
	"data": {
		"access_key": "FAKEKEYGUJD3PCIH4FIQ",
		"secret_key": "FAKESECRET/NNI/QJdIGbUyGolHhKZ0gd+IycSU3",
		"security_token": null
	},
	"warnings": null
}"""
    result_of_auth = json.loads(result_of_auth_json)
    result_of_read = json.loads(result_of_read_json)

    return (result_of_read, result_of_auth)

def output_aws_credentials(awscreds, awsaccount):
    """
    Format the credentials as a string containing the commands to define the ENV variables
    """
    aws_access_key_id = awscreds["data"]["access_key"]
    aws_secret_access_key = awscreds["data"]["secret_key"]
    shellenv_access = "export AWS_ACCESS_KEY_ID=%s" % aws_access_key_id
    shellenv_secret = "export AWS_SECRET_ACCESS_KEY=%s" % aws_secret_access_key
    results = "%s && %s" % (shellenv_access, shellenv_secret)
    return results

def update_aws_cred_file(awscreds, awsaccount, file_path):
    """
    Updates the credentials in file_path
    Use prefix in front of awsaccount
    """
    aws_access_key_id = awscreds["data"]["access_key"]
    aws_secret_access_key = awscreds["data"]["secret_key"]
    prefix = 'vault-'
    section = prefix + awsaccount
    file_path_expaneded = os.path.expanduser(file_path)

    awsconfig = configparser.SafeConfigParser()
    awsconfig.read(file_path_expaneded)
    try:
        awsconfig.set(section, "aws_access_key_id", aws_access_key_id)
        awsconfig.set(section, "aws_secret_access_key", aws_secret_access_key)
    except configparser.NoSectionError:
        awsconfig.add_section(section)
        awsconfig.set(section, "aws_access_key_id", aws_access_key_id)
        awsconfig.set(section, "aws_secret_access_key", aws_secret_access_key)

    with open(file_path_expaneded, 'wb') as configfile:
        awsconfig.write(configfile)

    results = "%s credentials updated in %s" % (section, file_path_expaneded)
    return results

def has_valid_perms(my_file):
    """
    Verify permissions of password and token files are 0600 (user:rw)
    Return true or false
    """
    my_file_full = os.path.expanduser(my_file)
    file_mode = stat.S_IMODE(os.stat(my_file_full).st_mode)
    logging.debug('check permission of file: %s (%s)' % (my_file_full, file_mode))
    if file_mode == stat.S_IWUSR + stat.S_IRUSR:
        return True
    else:
        return False

def get_session_token(token_file_path):
    """
    Take a file path and read a token from it
    Return empty string if file missing or empty
    """
    if os.path.isfile(os.path.expanduser(token_file_path)):
        with open(os.path.expanduser(token_file_path), 'r') as token_fd:
            token = token_fd.readline().strip()
    else:
        token = ''
    return token

def write_session_token(token_file_path, vault_token):
    """
    Take a file path and write vault_token to it
    """
    full_file_path = os.path.expanduser(token_file_path)
    logging.debug('writing token to a file (%s)' % full_file_path)
    with open(full_file_path, 'w') as full_fd:
        print(vault_token, file=full_fd)
    if not has_valid_perms(full_file_path):
        logging.debug('updating file perms on %s' % full_file_path)
        os.chmod(full_file_path, stat.S_IWUSR | stat.S_IRUSR)
    return



def main(argv=None):
    """
    Steps if script is run directly
    """
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(
        prog='getawscreds.py',
        description=HELP_MESSAGE,
        )
    # Determine verbosity (optional argument)
    parser.add_argument(
        "-v", "--verbose",
        help="increase output verbosity",
        action="store_true",
        default=False,
        )
    parser.add_argument(
        "-u", "--username",
        help="ldap username",
        required=True,
        )
    parser.add_argument(
        "-P", "--password-file",
        help="file which contains password",
        type=file,
        )
    parser.add_argument(
        "-a", "--address",
        help="address of the vault server (e.g. http://localhost:9000)",
        default=VAULT_ADDR,
        )
    parser.add_argument(
        "-n", "--account-name",
        help="name of aws account (e.g. engineering)",
        dest='account',
        required=True,
        )
    parser.add_argument(
        "-t", "--access-type",
        help="type of access needed (e.g. read, XXX, or superuser)",
        required=True,
        )
    parser.add_argument(
        "-o", "--output-credential-type",
        help="where to output credential from vault's results",
        choices=["shellenv", "credfile"],
        default="credfile",
        dest="output_to",
        )
    args = parser.parse_args()

    # Change log level if using verbose
    if args.verbose:
        logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.DEBUG)
        logging.info("Verbose logging.")
        logging.debug("Supplied Arguments: %s", args)
        logging.debug("Version: %s", VERINFO)
        logging.debug("DEFAULT_PASSWORD_FILE: %s" % DEFAULT_PASSWORD_FILE)
        logging.debug("VAULT_ADDR: %s" % VAULT_ADDR)
        logging.debug("VAULT_TOKEN: %s" % VAULT_TOKEN)
        logging.debug("AWS_CONFIG_FILE: %s" % AWS_CONFIG_FILE)
    else:
        logging.basicConfig(format="%(message)s", level=logging.INFO)

    logging.debug(args)

    if args.password_file:
        if not has_valid_perms(args.password_file.name):
            logging.warn('password file has wrong permissions (needs 0600): %s' % args.password_file.name)
            sys.exit(5)
    elif os.path.isfile(os.path.expanduser(VAULT_TOKEN)):
        if not has_valid_perms(VAULT_TOKEN):
            logging.warn('vault token file has wrong permissions (needs 0600): %s' % VAULT_TOKEN)
            sys.exit(7)

    client_data = {
        'username': args.username,
        'address': args.address,
        'password': 'password-goes-here-if-collected',
        }
    client_data['path'] = ''.join([
        args.account,
        '/creds/',
        args.access_type,
        ])
    logging.debug("client_data: %s", client_data)


    logging.debug('initlize vault client')
    client = hvac.Client(url=client_data['address'])

    vtoken = get_session_token(VAULT_TOKEN)
    client.token = vtoken
    logging.debug('vtoken: %s' % vtoken)

    if client.is_authenticated():
        logging.debug('client is authenticated, getting data')
        awscreds_from_vault = client.read(client_data['path'])
        vault_auth_output = 'successfully used existing token: %s' % client.token
    else:
        logging.debug('authenticating client')
        client_data['password'] = get_password(args.password_file)
        vault_auth_output = client.auth_ldap(client_data['username'], client_data['password'])

        if client.token != vtoken:
            write_session_token(VAULT_TOKEN, client.token)
        logging.debug('wrote token to file %s' % VAULT_TOKEN)
        logging.debug('token info (detailed): %s' % client.lookup_token())

        logging.debug('getting data')
        awscreds_from_vault = client.read(client_data['path'])

    logging.debug("awscreds_from_vault: %s", awscreds_from_vault)
    logging.debug("vault_auth_output: %s", vault_auth_output)

    if args.output_to == "shellenv":
        update_results = output_aws_credentials(awscreds_from_vault, args.account)
        print(update_results)
    elif args.output_to == "credfile":
        update_results = update_aws_cred_file(awscreds_from_vault,  args.account, AWS_CONFIG_FILE)
        logging.info(update_results)


if __name__ == "__main__":
    sys.exit(main())
