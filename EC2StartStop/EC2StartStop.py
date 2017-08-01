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


def get_time():
    return(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))

def get_ec2_monitor(instances):
    global filters
    ec2_monitor = pd.DataFrame(get_instance_attributes(instances))
    ec2_monitor = ec2_monitor[['Name','PrivateIpAddress','PublicIp','State','LaunchTime','InstanceId','FQDN','uptime_hours','StateCode','Platform','osuser','pemfile']]
    if filters == True:
        date_from = datetime.today() - relativedelta(months=1)
        ec2_monitor = ec2_monitor[ec2_monitor['LaunchTime'] > date_from]
    ec2_monitor.sort_values(['StateCode','Name',],ascending=[True,True],inplace=True)
    ec2_monitor = ec2_monitor.reset_index(drop=True)
    return ec2_monitor

def dns_records_clean(ln):
    ln['IP'] = ln['ResourceRecords'][0]['Value']
    ln['FQDN'] = ln['Name'][:-1]
    return ln

def get_fqdns():
    if get_config('HostedZoneId') != None:
        client = boto3.client('route53', aws_access_key_id=get_config('aws_access_key_id'), \
                          aws_secret_access_key=get_config('aws_secret_access_key'), \
                          region_name=get_config('region'))

        response = client.list_resource_record_sets(HostedZoneId=get_config('HostedZoneId'))
        dns_records = pd.DataFrame(response['ResourceRecordSets'])
        dns_records = dns_records[dns_records['Type'] == 'A']
        dns_records = dns_records.apply(dns_records_clean, axis=1)
        return dns_records



def get_instance_attributes(linstances):
    report_time_zone = get_config('timezone')
    localtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    localtime = pd.Timestamp(localtime, tz=report_time_zone)
    dattributes = []
    if get_config('HostedZoneId') != None:
        HosteZoneLookup = True
    else:
        HosteZoneLookup = False
    dns_records = get_fqdns()
    instance_connect = get_config('instance')
    default_pemfile = get_config('pemfile')
    for linstance in linstances['Reservations']:
        for x in range(0, len(linstance['Instances'])):
            attributes = {}
            if linstance['Instances'][x]['State']['Code'] != 48:
                attributes['InstanceId'] = linstance['Instances'][x]['InstanceId']
                for Tag in linstance['Instances'][x]['Tags']:
                    if Tag['Key'] == 'Name':
                        attributes['Name'] = Tag['Value']
                if 'Platform' in linstance['Instances'][x]:
                    attributes['Platform'] = linstance['Instances'][x]['Platform']
                else:
                    attributes['osuser'] = 'ec2-user'
                    attributes['pemfile'] = default_pemfile
                    for y in range(0,len(instance_connect)):
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
                else:
                    attributes['uptime_hours'] = ''
                attributes['PrivateIpAddress'] = linstance['Instances'][x]['PrivateIpAddress']
                if 'Association' in linstance['Instances'][x]['NetworkInterfaces'][0]:
                    attributes['PublicIp'] = linstance['Instances'][x]['NetworkInterfaces'][0]['Association']['PublicIp']
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
    head, tail = os.path.split(os.getcwd())
    filepath = os.path.join(head,'conf.json')
    with open(filepath) as configfile:
        configdata = simplejson.load(configfile)
    if attr in configdata:
        attr = configdata[attr]
        return attr

def get_client():
    client = boto3.client('ec2', aws_access_key_id=get_config('aws_access_key_id'), \
                          aws_secret_access_key=get_config('aws_secret_access_key'), \
                          region_name=get_config('region'))
    return client

def get_instances():
    try:
        instances = get_client().describe_instances()
    except Exception as e:
        error_text = 'Unexpected error: {0}'.format(e)
        click.echo(click.style(error_text, fg='red'))
    return instances

def get_instances_state():
    try:
        instances = get_instances()
        ec2_df = get_ec2_monitor(instances)
        nameLen = ec2_df.Name.map(len).max()
        fqdnLen = ec2_df.FQDN.map(len).max()
        for row in ec2_df.itertuples():
            table_line = '{0:3}|{1:{nameLen}}|{7:{fqdnLen}}|{2:15}|{3:15}|{4:8}|{5}|{8:4}|{6:19}|' \
            .format(row[0], row[1], row[2], row[3], row[4], row[5].strftime("%d/%m %H:%M"), row[6], row[7], row[8], \
            nameLen=nameLen, fqdnLen=fqdnLen)
            if row[4] == 'running':
                if row[8] > 8:
                    bold = True
                else:
                    bold = False
                click.echo(click.style(table_line, fg='green', bold=bold))
            elif row[4] in ('pending','stopping'):
                click.echo(click.style(table_line, fg='yellow'))
            else:
                click.echo(click.style(table_line, fg='white',))
    except:
        pass

def main():
#    click.clear()
    try:
        while True:
            state = getattr(sys, 'frozen', False)
            click.clear()
            print '{} - {} - Press: CTRL-C for all interactions'.format(get_time(), state)
            get_instances_state()
            time.sleep(300)
    except(KeyboardInterrupt):
        handle_main()

def handle_main():
    global filters
    click.echo('up, down, Down, filter, Filter, connect, quit ', nl=False)
    action = click.getchar()
    click.echo()
    if action == 'f':
        filters = True
        main()
    if action == 'F':
        filters = False
        main()
    if action == 'u':
        handle_start()
    if action == 'd':
        handle_stop()
    if action == 'D':
        handle_stopall()
    if action == 'c':
        handle_connect()
    if action == 'q':
        handle_exit()
    else:
        click.echo(click.style('Invalid action', fg='magenta'))
        time.sleep(2)
        main()

@click.command()
@click.option('--start', prompt='Instance to start', type=click.INT, help='Select stopped instance')

def handle_start(start):
    instances = get_instances()
    ec2_monitor = get_ec2_monitor(instances)
    try:
        state = ec2_monitor['State'][int(start)]
        if state == 'stopped':
            click.echo('Instance will be started %s' % start)
            id = ec2_monitor['InstanceId'][int(start)]
            instance_ids = []
            instance_ids.append(id)
            response = get_client().start_instances(InstanceIds=instance_ids)
            click.echo('Response %s' % response)
        else:
            click.echo(click.style('Instance is not in state stopped',fg='magenta'))
    except:
        click.echo(click.style('Invalid line index selection start',fg='magenta'))
    time.sleep(2)
    main()

@click.command()
@click.option('--stop', prompt='Instance to stop', type=click.INT, help='Select started instance')

def handle_stop(stop):
    instances = get_instances()
    ec2_monitor = get_ec2_monitor(instances)
    try:
        state = ec2_monitor['State'][int(stop)]
        if state == 'running':
            click.echo('Instance will be stopped %s' % stop)
            id = ec2_monitor['InstanceId'][int(stop)]
            instance_ids = []
            instance_ids.append(id)
            response = get_client().stop_instances(InstanceIds=instance_ids)
            click.echo('Response %s' % response)
        else:
            click.echo(click.style('Instance is not in state running',fg='magenta'))
    except:
        click.echo(click.style('Invalid line index selection stop',fg='magenta'))
    time.sleep(2)
    main()

def handle_stopall():
    instances = get_instances()
    ec2_monitor = get_ec2_monitor(instances)
    running = ec2_monitor[ec2_monitor['State'] == 'running']
    instance_ids = []
    for instance in running.itertuples():
        instance_ids.append(instance[6])
    response = get_client().stop_instances(InstanceIds=instance_ids)
    click.echo('Response %s' % response)
    time.sleep(2)
    main()

def handle_exit():
    click.clear()
    cover()
    sys.exit()

@click.command()
@click.option('--connect', prompt='Instance to connect', type=click.INT, help='Select started instance')

def handle_connect(connect):
    instances = get_instances()
    ec2_monitor = get_ec2_monitor(instances)
    MACOS = sys.platform.startswith('darwin')
    WINDOWS = sys.platform.startswith('win')
    domain = get_config('domain')
    domainUser= get_config('domainUser')

    state = ec2_monitor['State'][int(connect)]
    host = ec2_monitor['PrivateIpAddress'][int(connect)]
    pemfile = ec2_monitor['pemfile'][int(connect)]

    if WINDOWS:
        win = 'start mstsc /v {}'.format(host)
        lin = 'start cmd.exe /K bash ~ -c "ssh {}@{} -i {}"'.format(ec2_monitor['osuser'][connect], host, pemfile)
    elif MACOS:
        win = 'open rdp://full%20address=s:{}:3389&domain=s:{}&username=s:{}'.format(host, domain, domainUser)
        lin = 'osascript -e \'tell application "Terminal" to do script "ssh {}@{} -i {}"\''.format(ec2_monitor['osuser'][connect], host, pemfile)

    try:
        if state == 'running':
            if ec2_monitor['Platform'][connect] == 'windows':
                cmd = win
            else:
                cmd = lin
            os.system(cmd)
            click.echo(click.style(cmd, fg='yellow'))

        else:
            click.echo(click.style('Instance is not in state running',fg='magenta'))
    except:
        click.echo(click.style('Invalid line index selection connect',fg='magenta'))
    time.sleep(3)
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
    click.echo(click.style(covertext,fg='green'))
    time.sleep(2)

if __name__ == '__main__':
    global filters
    filters = True
    cover()
    main()