import os
import sys
import time
from pytz import timezone
import pandas as pd
import simplejson
import boto3
import click

from dataclasses import dataclass

from tabulate import tabulate

pdtabulate = lambda df:tabulate(df, headers='keys', tablefmt='psql')

SEP = '#' * 80

def get_client(service, key_id, key_secret, region):
    client = boto3.client(service, aws_access_key_id=key_id,
                          aws_secret_access_key=key_secret,
                          region_name=region)
    return client


@dataclass
class GlobalState:
    conf_file: str = ''
    config_data: dict = dict
    instances: dict = dict
    running_instances: dict = dict
    stopped_instances: dict = dict
    df_ec2_attributes: pd.core.frame.DataFrame = pd.DataFrame()

    def load_config_from_file(self):
        with open(self.conf_file) as file:
            self.config_data = simplejson.load(file)

    def set_instances(self):
        self.instances = get_client('ec2', self.config_data['aws_access_key_id'],
                                    self.config_data['aws_secret_access_key'],
                                    self.config_data['region'],
                                    ).describe_instances()

    def set_ec2_attributes(self):
        report_time_zone = self.config_data['timezone']
        localtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        localtime = pd.Timestamp(localtime, tz=report_time_zone)

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
                          'LocalLaunchTime': instance['LaunchTime'].astimezone(
                              timezone(self.config_data['timezone'])),
                          'PrivateIpAddress': instance['PrivateIpAddress'],
                          'PublicIp': instance['NetworkInterfaces'][0].get('Association', {'PublicIp': '-'}).get(
                              'PublicIp'),
                          'Platform': instance.get('Platform'),
                          'UptimeHours': 0,
                          'osUser': 'ec2-user',
                          'pemFile': self.config_data['pemfile'],
                          'EMRNodeType': ' '
                          }

            for tag in instance.get('Tags', {'Key': 'Name', 'Value': '-'}):
                if tag['Key'] == 'Name':
                    attributes['Name'] = tag['Value']
                if tag['Key'] == 'aws:elasticmapreduce:instance-group-role' and tag['Value'] == 'MASTER':
                    attributes['EMRNodeType'] = 'M'

            if instance['State']['Name'] == "running":
                self.running_instances.append(cntr)
                attributes['UptimeHours'] = int(
                    round((localtime - attributes['LocalLaunchTime']) / pd.Timedelta('1 hour')))

            if instance['State']['Name'] == "stopped":
                self.stopped_instances.append(cntr)

            for instance_con in self.config_data.get('instance'):
                if instance_con['InstanceId'] == instance['InstanceId']:
                    attributes['osUser'] = instance_con['osuser']
                    attributes['pemFile'] = instance_con['pemfile']

            ec2_attributes.append(attributes)

        df_ec2_attributes = pd.DataFrame(ec2_attributes)
        df_ec2_attributes = df_ec2_attributes.sort_values('Name')
        df_ec2_attributes = df_ec2_attributes.reset_index(drop=True)

        self.df_ec2_attributes = df_ec2_attributes


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
