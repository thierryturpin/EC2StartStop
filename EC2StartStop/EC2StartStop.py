# -*- coding: utf-8 -*-
"""
The EC2 monitor CLI
Monitors all EC2 instances related to an account.
The connect command will invoke the SSH command or the RDP application.
"""
import boto3
from datetime import datetime
from dateutil.relativedelta import relativedelta
import time
from pytz import timezone
import pandas as pd
import click
import simplejson
import os
import sys
import threading

class globState:

    @staticmethod
    def set_filter(filter):
        globState.cl_filter = filter

    @staticmethod
    def set_conf_file(conf_file):
        globState.cl_conf_file = conf_file

    @staticmethod
    def set_instances(instances):
        globState.cl_instances = instances


class cpuUsage:
    cl_instances_cpu = []

    @staticmethod
    def remove_prev_metric(instance):
        for k in cpuUsage.cl_instances_cpu:
            if k['InstanceId'] == instance:
                cpuUsage.cl_instances_cpu.remove(k)

    @staticmethod
    def get_cw_metrics(instances):
        for instance in instances:
            instance_cpu = {}
            cpu_utilization = get_cpu_utilization(instance)
            if len(cpu_utilization) > 0:
                cpuUsage.remove_prev_metric(instance)
                cpupct = cpu_utilization[-1]['Maximum']
                instance_cpu['InstanceId'] = instance
                instance_cpu['cpupct'] = cpupct
                for z in range(1, 6):
                    if z * 20 > cpupct:
                        break
                instance_cpu['cpupctblock'] = z
                cpuUsage.cl_instances_cpu.append(instance_cpu)
                #print('metrics collection done')

    @staticmethod
    def get_instance_cpupctblock(instance):
        for instances_cpu in cpuUsage.cl_instances_cpu:
            if instance == instances_cpu['InstanceId']:
                return instances_cpu['cpupctblock']

# TODO
# Add a search option
# Check motd for putty

def get_time():
    return time.strftime("%d/%m/%Y %H:%M:%S", time.localtime())


def get_cpu_utilization(instance_id):

    now = datetime.utcnow()
    response = get_client('cloudwatch').get_metric_statistics(
        Namespace='AWS/EC2',
        MetricName='CPUUtilization',
        Dimensions=[
            {'Name': 'InstanceId', 'Value': instance_id},
        ],
        StartTime=now-relativedelta(minutes=10),
        EndTime=now,
        Period=300,
        Statistics=['Maximum'],
    )

    # return chronological results
    return sorted(response['Datapoints'], key=lambda x: x['Timestamp'])


def get_ec2_monitor(instances):
    """Format dataframe, column order. Only dipslay instaces of the last month. Order by instance description.
    """
    ec2_monitor = pd.DataFrame(get_instance_attributes(instances))
    ec2_monitor = ec2_monitor[
        ['Name', 'PrivateIpAddress', 'PublicIp', 'State', 'LaunchTime', 'InstanceId', 'FQDN', 'uptime_hours',
         'StateCode', 'Platform', 'osuser', 'pemfile', 'EMRNodeType', 'cpu', 'InstanceType']]
    if globState.cl_filter:
        date_from = datetime.today() - relativedelta(months=1)
        ec2_monitor = ec2_monitor[ec2_monitor['LaunchTime'] > date_from]
    ec2_monitor.sort_values(['Name', ], ascending=[True], inplace=True)
    ec2_monitor = ec2_monitor.reset_index(drop=True)
    return ec2_monitor


def dns_records_clean(ln):
    ln['IP'] = ln['ResourceRecords'][0]['Value']
    ln['FQDN'] = ln['Name'][:-1]
    return ln


def get_fqdns():
    """If a hosted zone is foreseen, get DNS records.
    """
    if get_config('HostedZoneId') is not None:
        response = get_client('route53').list_resource_record_sets(HostedZoneId=get_config('HostedZoneId'))
        dns_records = pd.DataFrame(response['ResourceRecordSets'])
        dns_records = dns_records[dns_records['Type'] == 'A']
        dns_records = dns_records.apply(dns_records_clean, axis=1)
        return dns_records


def get_instance_attributes(linstances):
    """Format the dataframe.
       Terminated instances are not listed - state 48.
       Get the name tags, platform.
       Get the uptime of the instance.
    """
    report_time_zone = get_config('timezone')
    localtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    localtime = pd.Timestamp(localtime, tz=report_time_zone)
    dattributes = []
    if get_config('HostedZoneId') is None:
        HosteZoneLookup = False
    else:
        HosteZoneLookup = True
    dns_records = get_fqdns()
    instance_connect = get_config('instance')
    default_pemfile = get_config('pemfile')
    for linstance in linstances['Reservations']:
        for x in range(0, len(linstance['Instances'])):
            attributes = {}
            if linstance['Instances'][x]['State']['Code'] != 48:
                attributes['InstanceId'] = linstance['Instances'][x]['InstanceId']
                attributes['InstanceType'] = linstance['Instances'][x]['InstanceType']
                for Tag in linstance['Instances'][x]['Tags']:
                    if Tag['Key'] == 'Name':
                        attributes['Name'] = Tag['Value']
                    if Tag['Key'] == 'aws:elasticmapreduce:instance-group-role':
                        if Tag['Value'] == 'MASTER':
                            attributes['EMRNodeType'] = 'M'
                if 'Name' not in attributes:
                    attributes['Name'] = '-'
                if 'EMRNodeType' not in attributes:
                    attributes['EMRNodeType'] = ' '
                if 'Platform' in linstance['Instances'][x]:
                    attributes['Platform'] = linstance['Instances'][x]['Platform']
                else:
                    attributes['osuser'] = 'ec2-user'
                    attributes['pemfile'] = default_pemfile
                    for y in range(0, len(instance_connect)):
                        if attributes['InstanceId'] in instance_connect[y]['InstanceId']:
                            attributes['osuser'] = instance_connect[y]['osuser']
                            attributes['pemfile'] = instance_connect[y]['pemfile']
                attributes['State'] = linstance['Instances'][x]['State']['Name']
                attributes['StateCode'] = linstance['Instances'][x]['State']['Code']
                LocalLaunchTime = linstance['Instances'][x]['LaunchTime']
                LocalLaunchTime = LocalLaunchTime.astimezone(timezone(report_time_zone))
                attributes['LaunchTime'] = LocalLaunchTime
                if attributes['State'] == 'running':
                    uptime = localtime - LocalLaunchTime
                    uptime_hours = uptime / pd.Timedelta('1 hour')
                    uptime_hours = int(round(uptime_hours))
                    attributes['uptime_hours'] = uptime_hours
                    cpupctblock = cpuUsage.get_instance_cpupctblock(attributes['InstanceId'])
                    if cpupctblock is not None:
                        attributes['cpu'] = '#' * cpupctblock
                else:
                    attributes['uptime_hours'] = ''
                    attributes['cpu'] = ' ' * 5
                attributes['PrivateIpAddress'] = linstance['Instances'][x]['PrivateIpAddress']
                if 'Association' in linstance['Instances'][x]['NetworkInterfaces'][0]:
                    attributes['PublicIp'] = linstance['Instances'][x]['NetworkInterfaces'][0]['Association'][
                        'PublicIp']
                else:
                    attributes['PublicIp'] = '-'
                if HosteZoneLookup:
                    num_dns_records = len(dns_records[(dns_records['IP'] == attributes['PrivateIpAddress'])]['FQDN'])
                    if num_dns_records == 1:
                        attributes['FQDN'] = dns_records[(dns_records['IP'] == attributes['PrivateIpAddress'])]['FQDN'].values[0]
                    else:
                        attributes['FQDN'] = '-'
                else:
                    attributes['FQDN'] = '-'
                dattributes.append(attributes)
    return dattributes


def get_config(attr):
    with open(globState.cl_conf_file) as configfile:
        configdata = simplejson.load(configfile)
    if attr in configdata:
        attr = configdata[attr]
        return attr


def get_client(service):
    client = boto3.client(service, aws_access_key_id=get_config('aws_access_key_id'),
                          aws_secret_access_key=get_config('aws_secret_access_key'),
                          region_name=get_config('region'))
    return client


def get_instances():
    try:
        instances = get_client('ec2').describe_instances()
        return instances
    except Exception as e:
        error_text = 'Unexpected error: {0}'.format(e)
        click.echo(click.style(error_text, fg='red'))


def get_cpu_metrics():
    while True:
        instances = get_instances()
        cpu_for_instances = []
        for instance in instances['Reservations']:
            for x in range(0, len(instance['Instances'])):
                if instance['Instances'][x]['State']['Code'] == 16:
                    InstanceId = instance['Instances'][x]['InstanceId']
                    cpu_for_instances.append(InstanceId)
        cpuUsage.get_cw_metrics(cpu_for_instances)
        time.sleep(90)


def get_instances_state(instances):
    """Get data frame with all instances and return the refresh rate for the CLI.
       Default refresh rate is 1 minute. Unless starting/stopping instances, refresh rate is 3 seconds.
       If uptime > 8H mark in bold.
    """
    refresh_rate = 60
    try:
        ec2_df = get_ec2_monitor(instances)
        nameLen = ec2_df.Name.astype(str).map(len).max()
        fqdnLen = ec2_df.FQDN.astype(str).map(len).max()
        typeLen = ec2_df.InstanceType.astype(str).map(len).max()

        click.clear()
        print('{} - Press: CTRL-C for all interactions'.format(get_time()))
        for row in ec2_df.itertuples():
            table_line = '{0:3}|{1:{nameLen}}|{9}|{7:{fqdnLen}}|{2:15}|{3:15}|{4:14}|{5} --{8:5}|{6:19}|{10:5}|{11:{typeLen}}|' \
                .format(row[0], row[1], row[2], row[3], row[4], row[5].strftime("%d/%m/%y %H:%M"), row[6], row[7], row[8], row[13], row[14], row[15],
                        nameLen=nameLen, fqdnLen=fqdnLen, typeLen=typeLen)
            if row[4] == 'running':
                if row[8] > 8:
                    bold = True
                else:
                    bold = False
                click.echo(click.style(table_line, fg='green', bold=bold))
            elif row[4] in ('pending', 'stopping'):
                click.echo(click.style(table_line, fg='yellow'))
                refresh_rate = 3
            else:
                click.echo(click.style(table_line, fg='white', ))
    except:
        click.echo(click.style('Unhandled error', fg='red'))
    return refresh_rate


@click.command()
@click.argument('conf_file')
def get_config_file(conf_file):
    """The program takes 1 argument the conf file.
    A conf file template can be found in: template.conf.json
    All further interactions are by CTRL-C.
    """
    if os.path.isfile(conf_file):
        globState.set_conf_file(conf_file)
        globState.cl_filter = get_config('filter')
        globState.cl_daemon_state = False
        main()
    else:
        click.echo(click.style('Parameter is not a file, configuration file. See --help.', fg='red'))
        time.sleep(3)


def main():
    try:
        while True:
            globState.set_instances(get_instances())
            if not globState.cl_daemon_state:
                t1 = threading.Thread(target=get_cpu_metrics)
                t1.daemon = True
                t1.start()
                globState.cl_daemon_state = True

            time.sleep(get_instances_state(globState.cl_instances))
    except KeyboardInterrupt:
        handle_main()


def handle_main():
    click.echo('up, down, Down, filter, Filter, connect, quit ', nl=False)
    action = click.getchar()
    click.echo()
    if action == 'f':
        globState.set_filter(True)
        main()
    if action == 'F':
        globState.set_filter(False)
        main()
    if action == 'u':
        handle_start()
    if action == 'd':
        handle_stop()
    if action == 'D':
        if get_config('stop_all_enabled'):
            handle_stopall()
        else:
            click.echo(click.style('Stop all disabled by configuration', fg='magenta'))
            time.sleep(2)
            main()
    if action == 'c':
        handle_connect()
    if action == 'q':
        handle_exit()
    else:
        click.echo(click.style('Invalid action', fg='magenta'))
        time.sleep(1)
        main()


@click.command()
@click.option('--start', prompt='Instance to start', type=click.INT, help='Select stopped instance')
@click.argument('conf_file')  # Do not remove, enforced by click
def handle_start(start, conf_file):
    ec2_monitor = get_ec2_monitor(globState.cl_instances)
    try:
        state = ec2_monitor['State'][int(start)]
        if state == 'stopped':
            click.echo('Instance will be started: %s' % start)
            id = ec2_monitor['InstanceId'][int(start)]
            instance_ids = []
            instance_ids.append(id)
            response = get_client('ec2').start_instances(InstanceIds=instance_ids)
            #click.echo('Response %s' % response)
        else:
            click.echo(click.style('Instance is not in state stopped', fg='magenta'))
    except:
        click.echo(click.style('Invalid line index selection start', fg='magenta'))
    main()


@click.command()
@click.option('--stop', prompt='Instance to stop', type=click.INT, help='Select started instance')
@click.argument('conf_file')
def handle_stop(stop, conf_file):  # Do not remove, enforced by click
    ec2_monitor = get_ec2_monitor(globState.cl_instances)
    try:
        state = ec2_monitor['State'][int(stop)]
        if state == 'running':
            click.echo('Instance will be stopped: %s' % stop)
            id = ec2_monitor['InstanceId'][int(stop)]
            instance_ids = []
            instance_ids.append(id)
            response = get_client('ec2').stop_instances(InstanceIds=instance_ids)
            #click.echo('Response %s' % response)
        else:
            click.echo(click.style('Instance is not in state running', fg='magenta'))
    except:
        click.echo(click.style('Invalid line index selection stop', fg='magenta'))
    main()

@click.command()
@click.option('--confirm', prompt='Confirm shut-down of all intances! y/n', type=click.Choice(['y', 'n']))
@click.argument('conf_file')
def handle_stopall(confirm, conf_file):  # Do not remove, enforced by click
    if confirm == 'y':
        ec2_monitor = get_ec2_monitor(globState.cl_instances)
        running = ec2_monitor[ec2_monitor['State'] == 'running']
        instance_ids = []
        for instance in running.itertuples():
            instance_ids.append(instance[6])
        response = get_client('ec2').stop_instances(InstanceIds=instance_ids)
        #click.echo('Response %s' % response)
        time.sleep(2)
    main()


def handle_exit():
    click.clear()
    cover()
    sys.exit()


@click.command()
@click.option('--connect', prompt='Instance to connect', type=click.INT, help='Select started instance')
@click.argument('conf_file')
def handle_connect(connect, conf_file):  # Do not remove, enforced by click
    """Fun with quotes.
    Python needs a \ to escape a \
    In osascript a double quote " needs to be escaped with a \
    """
    ec2_monitor = get_ec2_monitor(globState.cl_instances)
    MACOS = sys.platform.startswith('darwin')
    WINDOWS = sys.platform.startswith('win')
    domain = get_config('domain')
    domainUser = get_config('domainUser')

    state = ec2_monitor['State'][int(connect)]
    pemfile = ec2_monitor['pemfile'][int(connect)]
    ip = ec2_monitor['PrivateIpAddress'][int(connect)]
    fqdn = ec2_monitor['FQDN'][int(connect)]
    name = ec2_monitor['Name'][int(connect)]
    addr = ip

    if WINDOWS:
        win = 'start mstsc /v {}'.format(addr)
        if get_config('winssh') == 'WSL':
            lin = 'start cmd.exe /K bash ~ -c "ssh {}@{} -i {}"'.format(ec2_monitor['osuser'][connect], addr, pemfile)
        elif get_config('winssh') == 'putty':
            lin = 'start putty.exe -ssh -i {} {}@{}'.format(pemfile, ec2_monitor['osuser'][connect], addr)
    elif MACOS:
        win = 'open rdp://full%20address=s:{}:3389&domain=s:{}&username=s:{}'.format(addr, domain, domainUser)

        sep = '#' * 80
        mottdtxt = 'EC2 name: {name}\\nDNS name: {fqdn}'.format(name=name, fqdn=fqdn)
        motdtt = '{sep}\\n{mottdtxt} \\n{sep}\\n'.format(sep=sep, mottdtxt=mottdtxt)
        lin = '''osascript <<EOD
                    tell application "Terminal" to do script "ssh {}@{} \\
                                                              -i {} \\
                                                              -t 'clear;tput setaf 2;cat /etc/motd;echo -n \\"{}\\" ;tput sgr0; bash -i'"
                 '''.format(ec2_monitor['osuser'][connect], addr, pemfile, motdtt)
        lin += '\n' + 'EOD'

    try:
        if state == 'running':
            if ec2_monitor['Platform'][connect] == 'windows':
                cmd = win
            else:
                cmd = lin
            os.system(cmd)
            click.echo(click.style(cmd, fg='yellow'))

        else:
            click.echo(click.style('Instance is not in state running', fg='magenta'))
    except:
        click.echo(click.style('Invalid line index selection connect', fg='magenta'))
    time.sleep(2)
    main()


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


if __name__ == '__main__':
    cover()
    get_config_file()
