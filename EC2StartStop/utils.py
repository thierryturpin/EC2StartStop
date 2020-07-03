import sys
import pandas as pd
import simplejson
import boto3
from botocore.exceptions import ClientError
import click
import arrow

from dataclasses import dataclass, field

from tabulate import tabulate

pdtabulate = lambda df: tabulate(df, headers='keys', tablefmt='psql')

SEP = '#' * 80


def get_client(service, key_id, key_secret, region):
    try:
        client = boto3.client(service, aws_access_key_id=key_id,
                              aws_secret_access_key=key_secret,
                              region_name=region)

    except ClientError as error:
        click.echo(click.style(f'boto3 ClientError: {error}', fg='red'))
        sys.exit()

    return client


def empty_dict():
    return {}


@dataclass
class GlobalState:
    conf_file: str = ''
    config_data: dict = dict
    instances: dict = dict
    running_instances: list = list
    stopped_instances: list = list
    df_ec2_attributes: pd.core.frame.DataFrame = pd.DataFrame()
    a_dns_records: pd.core.frame.DataFrame = pd.DataFrame()
    ec2_instance_count: int = 0
    cw_cpu_thread_started: bool = False
    cpu_for_instance: dict = field(default_factory=empty_dict)
    search_match_string: str = ''

    def set_route53_records(self):
        def get_ip_fqdn(record):
            record['IP'] = record['ResourceRecords'][0]['Value']
            record['FQDN'] = record['Name'][:-1]

            return record

        all_dns_records = pd.DataFrame(get_client('route53', self.config_data['aws_access_key_id'],
                                                  self.config_data['aws_secret_access_key'],
                                                  self.config_data['region'],
                                                  ).list_resource_record_sets(
            HostedZoneId=self.config_data.get('HostedZoneId'))[
                                           'ResourceRecordSets'])

        a_dns_records = all_dns_records[all_dns_records['Type'] == 'A']
        self.a_dns_records = a_dns_records.apply(get_ip_fqdn, axis=1)

    def load_config_from_file(self):
        with open(self.conf_file) as file:
            self.config_data = simplejson.load(file)

    def set_instances(self):
        self.instances = get_client('ec2', self.config_data['aws_access_key_id'],
                                    self.config_data['aws_secret_access_key'],
                                    self.config_data['region'],
                                    ).describe_instances()

    def set_ec2_attributes(self):
        instances = [x['Instances'] for x in self.instances['Reservations']]
        non_terminated_instances = [x for y in instances for x in y if x['State']['Code'] != 48]

        ec2_attributes = []
        self.running_instances = []
        self.stopped_instances = []

        for cntr, instance in enumerate(non_terminated_instances):
            attributes = {'InstanceId': instance['InstanceId'],
                          'InstanceType': instance['InstanceType'],
                          'State': instance['State']['Name'],
                          'StateCode': instance['State']['Code'],
                          'LocalLaunchTime': arrow.get(instance['LaunchTime']).to(self.config_data['timezone']),
                          'PrivateIpAddress': instance['PrivateIpAddress'],
                          'PublicIp': instance['NetworkInterfaces'][0].get('Association', {'PublicIp': '-'}).get(
                              'PublicIp'),
                          'FQDN': '-',
                          'Platform': instance.get('Platform'),
                          'Uptime': '',
                          'osUser': 'ec2-user',
                          'pemFile': self.config_data['pemfile'],
                          'EMRNodeType': ' '
                          }

            if self.config_data.get('HostedZoneId') is not None:
                fqdn = self.a_dns_records[self.a_dns_records['IP'] == instance['PrivateIpAddress']].to_dict('records')
                if fqdn:
                    attributes['FQDN'] = fqdn[0].get('FQDN')

            tags = instance.get('Tags', [{'Key': 'Name', 'Value': '-'}])
            for tag in tags:
                if tag['Key'] == 'Name':
                    attributes['Name'] = tag['Value']
                if tag['Key'] == 'aws:elasticmapreduce:instance-group-role' and tag['Value'] == 'MASTER':
                    attributes['EMRNodeType'] = 'M'

            if instance['State']['Name'] == "running":
                self.running_instances.append(instance['InstanceId'])
                attributes['Uptime'] = arrow.get(attributes['LocalLaunchTime']).humanize(only_distance=True)

            if instance['State']['Name'] == "stopped":
                self.stopped_instances.append(instance['InstanceId'])

            for instance_con in self.config_data.get('instance'):
                if instance_con['InstanceId'] == instance['InstanceId']:
                    attributes['osUser'] = instance_con['osuser']
                    attributes['pemFile'] = instance_con['pemfile']

            ec2_attributes.append(attributes)

        df_ec2_attributes = pd.DataFrame(ec2_attributes)
        df_ec2_attributes = df_ec2_attributes.sort_values('Name')
        df_ec2_attributes = df_ec2_attributes.reset_index(drop=True)

        self.df_ec2_attributes = df_ec2_attributes
        self.ec2_instance_count = df_ec2_attributes.shape[0] - 1


def cover():
    covertext = '''

     _______   ______ ___   
    |   ____| /      |__ \  
    |  |__   |  ,----'  ) | 
    |   __|  |  |      / /  
    |  |____ |  `----./ /_  
    |_______| \______|____| 

    .___  ___.   ______   .__   __.  __  .___________.  ______   .______      
    |   \/   |  /  __  \  |  \ |  | |  | |           | /  __  \  |   _  \     
    |  \  /  | |  |  |  | |   \|  | |  | `---|  |----`|  |  |  | |  |_)  |    
    |  |\/|  | |  |  |  | |  . `  | |  |     |  |     |  |  |  | |      /     
    |  |  |  | |  `--'  | |  |\   | |  |     |  |     |  `--'  | |  |\  \----.
    |__|  |__|  \______/  |__| \__| |__|     |__|      \______/  | _| `._____|


    T. Turpin

                                                                          '''
    click.echo(click.style(covertext, fg='green'))
