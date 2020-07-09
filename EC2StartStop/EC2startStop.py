"""
The EC2 monitor CLI
Monitors all EC2 instances related to an account.
The connect command will invoke the SSH command or the RDP application.
"""
import os
import sys
import time
import threading
import re
import click
import arrow

from utils import SEP, GlobalState, get_client, cover

global_state = GlobalState()


@click.command()
@click.argument('conf_file')
def click_get_config_file(conf_file):
    """
    The program takes 1 argument the conf file.
    A conf file template can be found in: template.conf.json
    All further interactions are by CTRL-C.
    """
    if os.path.isfile(conf_file):
        global_state.conf_file = conf_file
        global_state.load_config_from_file()
    else:
        click.echo(click.style('Parameter is not a configuration file. See --help.', fg='red'))
        time.sleep(3)


@click.command()
@click.option('--connect', prompt='Instance to connect', type=click.INT, help='Select started instance')
@click.argument('conf_file')
def handle_connect(connect, conf_file):
    if connect < 0 or connect > global_state.ec2_instance_count:
        click.echo(click.style(f'Invalid number: {connect}', fg='red'))

    elif global_state.df_ec2_attributes['InstanceId'][connect] not in global_state.running_instances:
        click.echo(click.style(f'The selected line {connect} is not in a running state', fg='red'))
    else:
        ip = global_state.df_ec2_attributes['PrivateIpAddress'][connect]
        name = global_state.df_ec2_attributes['Name'][connect]
        os_user = global_state.df_ec2_attributes['osUser'][connect]
        pem_file = global_state.df_ec2_attributes['pemFile'][connect]

        if sys.platform.startswith('win'):
            if global_state.df_ec2_attributes['Platform'][connect] == 'windows':
                cmd = f"start mstsc /v {ip}"
            else:
                if global_state.config_data['winssh'] == 'WSL':
                    cmd = f'start cmd.exe /K bash ~ -c "ssh {os_user}@{ip} -i {pem_file}"'
                if global_state.config_data['winssh'] == 'putty':
                    cmd = f'start putty.exe -ssh -i {pem_file} {os_user}@{ip}'

        if sys.platform.startswith('darwin'):
            if global_state.df_ec2_attributes['Platform'][connect] == 'windows':
                cmd = \
                    f"""
                    open "rdp://full%20address=s:{ip}:3389&domain=s:{global_state.config_data['domain']}&username=s:{global_state.config_data['domainUser']}"
                    """
            else:
                banner = f'{SEP}\\nEC2 name: {name}\\n{SEP}\\n'
                cmd = \
                    f"""
                        osascript <<EOD
                        tell application "Terminal" to do script "ssh {os_user}@{ip} \\
                                                                  -i {pem_file} \\
                                                                  -t 'clear;tput setaf 2;cat /etc/motd;echo -n \\"{banner}\\" ;tput sgr0; bash -i'"
                    """
                cmd += '\n' + 'EOD'

        os.system(cmd)
        click.echo(click.style(cmd, fg='yellow'))

    time.sleep(1)
    main_loop()


@click.command()
@click.option('--start', prompt='Instance to start', type=click.INT, help='Select stopped instance')
@click.argument('conf_file')
def handle_start(start, conf_file):
    if start < 0 or start > global_state.ec2_instance_count:
        click.echo(click.style(f'Invalid number: {start}', fg='red'))

    elif global_state.df_ec2_attributes['InstanceId'][start] not in global_state.stopped_instances:
        click.echo(click.style(f'The selected line {start} is not in a stopped state', fg='red'))

    else:
        get_client('ec2', global_state.config_data['aws_access_key_id'],
                   global_state.config_data['aws_secret_access_key'],
                   global_state.config_data['region']).start_instances(
            InstanceIds=[global_state.df_ec2_attributes['InstanceId'][start]])

    main_loop()


@click.command()
@click.option('--stop', prompt='Instance to stop', type=click.INT, help='Select started instance')
@click.argument('conf_file')
def handle_stop(stop, conf_file):
    if stop < 0 or stop > global_state.ec2_instance_count:
        click.echo(click.style(f'Invalid number: {stop}', fg='red'))
    elif global_state.df_ec2_attributes['InstanceId'][stop] not in global_state.running_instances:
        click.echo(click.style(f'The selected line {stop} is not in a running state', fg='red'))

    else:
        get_client('ec2', global_state.config_data['aws_access_key_id'],
                   global_state.config_data['aws_secret_access_key'],
                   global_state.config_data['region']).stop_instances(
            InstanceIds=[global_state.df_ec2_attributes['InstanceId'][stop]])
    main_loop()


@click.command()
@click.option('--search', prompt='Search text', type=click.STRING, default='', help='Enter the text to match')
@click.argument('conf_file')  
def handle_search(search, conf_file):
    global_state.search_match_string = search
    main_loop()


def print_instances_grid():
    """
    Print a formatted output of the dataframe
    :return: refresh rate, if instances state is changing, lower the rate
    """
    refresh_rate = 30

    global_state.set_ec2_attributes()

    name_len = global_state.df_ec2_attributes.Name.astype(str).map(len).max()
    uptime_len = global_state.df_ec2_attributes.Uptime.astype(str).map(len).max()
    type_len = global_state.df_ec2_attributes.InstanceType.astype(str).map(len).max()
    fqdn_len = global_state.df_ec2_attributes.FQDN.astype(str).map(len).max()

    click.clear()
    print(f"{arrow.now().format('YYYY-MM-DD HH:mm:ss')} Press: CTRL-C for all interactions")

    for cntr, row in global_state.df_ec2_attributes.iterrows():
        # default values
        color = 'white'
        cpu_for_instance = ''
        reverse = False

        if (global_state.search_match_string != '' and re.search(global_state.search_match_string, row['Name'],
                                                                 re.IGNORECASE)) or \
                (global_state.search_match_string != '' and re.search(global_state.search_match_string,
                                                                      row['InstanceId'], re.IGNORECASE)):
            reverse = True

        if row['State'] == 'running':
            color = 'green'
            cpu_for_instance = u'\u2589' * int(global_state.cpu_for_instance.get(row['InstanceId'], 0) // 10)
        elif row['State'] in ('pending', 'stopping'):
            color = 'yellow'
            refresh_rate = 3

        table_line = f"{cntr:3}|{row['Name']:<{name_len}}|{row['EMRNodeType']}|{row['PrivateIpAddress']:<15}|" \
                     f"{row['PublicIp']:<15}|{row['FQDN']:<{fqdn_len}}|" \
                     f"{row['State']:<14}|{row['LocalLaunchTime'].strftime('%d/%m/%y %H:%M')}|" \
                     f"{row['Uptime']:{uptime_len}}|{row['InstanceId']:<19}|" \
                     f"{row['InstanceType']:{type_len}}|{cpu_for_instance:<10}|"

        click.echo(click.style(table_line, fg=color, reverse=reverse))

    return refresh_rate


def handle_exit():
    click.clear()
    cover()
    sys.exit()


def handle_user_input():
    """
    Handle all keyboard input
    """
    click.echo('up, down, connect, quit, refresh, /', nl=False)
    action = click.getchar()
    click.echo()
    if action == 'q':
        handle_exit()
    if action == 'c':
        handle_connect()
    if action == 'u':
        handle_start()
    if action == 'd':
        handle_stop()
    if action == '%':  # only for debug
        print(global_state)
        handle_exit()
    if action == 'r':
        main_loop()
    if action == '/':
        handle_search()
    else:
        click.echo(click.style('Invalid action', fg='red'))
        time.sleep(1)
        main_loop()


def get_cpu_metrics_for_instance(instance_id):
    """
    Get CPUUtilization for the EC2 instance
    :param instance_id:
    :return:
    """
    now = arrow.utcnow()
    response = get_client('cloudwatch', global_state.config_data['aws_access_key_id'],
                          global_state.config_data['aws_secret_access_key'],
                          global_state.config_data['region']).get_metric_statistics(
        Namespace='AWS/EC2',
        MetricName='CPUUtilization',
        Dimensions=[
            {'Name': 'InstanceId', 'Value': instance_id},
        ],
        StartTime=now.shift(minutes=-60).naive,
        EndTime=now.naive,
        Period=300,
        Statistics=['Maximum'],
    )

    # return chronological results
    return sorted(response['Datapoints'], key=lambda x: x['Timestamp'])


def get_cpu_metrics_for_instances():
    """
    Running in a separate thread, getting the CW metrics can be slow
    :return:
    """
    while True:
        for instance in global_state.running_instances:
            cpu_for_instance = get_cpu_metrics_for_instance(instance)
            if cpu_for_instance:
                global_state.cpu_for_instance.update({instance: cpu_for_instance[-1]['Maximum']})

        time.sleep(90)


def main_loop():
    """
    The main loop is a separate function, because after input is handled, the main loop needs to be called again
    :return:
    """
    if global_state.config_data.get('HostedZoneId') is not None:
        global_state.set_route53_records()
    try:
        while True:
            global_state.set_instances()
            refresh = print_instances_grid()

            if not global_state.cw_cpu_thread_started:
                t1 = threading.Thread(target=get_cpu_metrics_for_instances)
                t1.daemon = True
                t1.start()
                global_state.cw_cpu_thread_started = True

            time.sleep(refresh)

    except KeyboardInterrupt:
        handle_user_input()


if __name__ == '__main__':
    cover()
    click_get_config_file.main(standalone_mode=False)
    main_loop()
