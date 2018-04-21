# -*- coding: utf-8 -*-
import argparse
import json
import logging
import os
import subprocess

logger = logging.getLogger(__name__)

base_dir = 'crypto-config'


def get_open_ssl_config_path():
    return os.path.join(base_dir, 'openssl.cnf')


def generate(config_path, output_dir):
    with open(config_path) as data_file:
        config_data = json.load(data_file)

    for org_spec in config_data['PeerOrgs']:
        # fill it for ca
        org_spec['CA']['Org'] = org_spec['Domain']
        generate_peer_org(output_dir, org_spec)


def init_dirs(dirs):
    for the_dir in dirs:
        if not os.path.exists(the_dir):
            os.makedirs(the_dir)


def generate_peer_org(output_dir, org_spec):
    org_name = org_spec['Domain']

    org_dir = os.path.join(output_dir, 'peerOrganizations', org_name)
    ca_dir = os.path.join(org_dir, 'ca')
    tls_ca_dir = os.path.join(org_dir, 'tlsca')
    msp_dir = os.path.join(org_dir, 'msp')
    peer_dir = os.path.join(org_dir, 'peers')
    users_dir = os.path.join(org_dir, 'users')
    admin_cert_dir = os.path.join(msp_dir, 'admincerts')

    init_dirs([org_dir, ca_dir, tls_ca_dir, msp_dir, peer_dir, users_dir, admin_cert_dir])

    # generate signing CA
    new_ca(ca_dir, org_name, org_spec['CA'])

    # generate TLS CA


def new_ca(output_dir, org_name, ca_config):
    private_key_path = os.path.join(output_dir, 'ca_sk')
    generate_private_key(private_key_path)
    csr_path = os.path.join(output_dir, 'ca.csr')
    generate_csr(private_key_path, ca_config, csr_path)
    generate_cert(private_key_path, csr_path, os.path.join(output_dir, 'ca.{}.perm'.format(org_name)))


def split_command_line(cmd):
    return cmd.split()


def run_command(cmd):
    subprocess.Popen(cmd, shell=True)


def generate_private_key(key_store_path):
    run_command('openssl ecparam -genkey -name prime256v1 -noout -out {}'.format(key_store_path))


def generate_csr(private_key, ca_config, csr_path):
    the_subject = csr_subject(country=ca_config['Country'], state=ca_config['Province'], location=ca_config['Locality'],
                              org=ca_config['Org'], org_unit=ca_config['OrganizationalUnit'],
                              common_name=ca_config['CommonName'])
    if ca_config['SANS']:
        config_option = cmd_sans(ca_config['SANS'])
        run_command(
            'openssl req -new -key {} -out {} -subj "{}" {}'.format(private_key, csr_path, the_subject, config_option))

    else:
        run_command('openssl req -new -key {} -out {} -subj "{}"'.format(private_key, csr_path, the_subject))


def add_sans_to_config(sans_str):
    from shutil import copyfile

    dst_file = get_open_ssl_config_path()
    copyfile('/etc/ssl/openssl.cnf', dst_file)
    with open(dst_file, "a") as myfile:
        myfile.write(sans_str)
    return dst_file


def cmd_sans(sans):
    subject_alt_name = ','.join(['DNS.{}:{}'.format(i, domain) for i, domain in enumerate(sans)])
    sans_append = '[SAN]\nsubjectAltName={}'.format(subject_alt_name)
    config_file = add_sans_to_config(sans_append)
    return '-config {}'.format(config_file)


def generate_cert(private_key, csr_path, cert_path, public_key=None):
    run_command('openssl req -in {} -key {} -x509 -nodes -days 3650 -out {}'.format(csr_path, private_key, cert_path))


def csr_subject(country='CN', state='SICHUANG', location='CHENGDU', org='HCB', org_unit='TECH',
                common_name='tech.wlqq.com'):
    return '/C={}/ST={}/L={}/O={}/OU={}/CN={}'.format(country, state, location, org, org_unit, common_name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('cmd', choices=['generate', 'showtemplate', 'extend'], default='generate',
                        help="Current support cmd")
    parser.add_argument('-o', '--output', default='crypto-config',
                        help='The output directory in which to place artifacts')
    parser.add_argument('-f', '--config', default='crypto-config.json', help='The configuration template to use')

    args = parser.parse_args()

    if args.cmd == 'generate':
        if args.output:
            base_dir = args.output

        generate(args.config, args.output)
