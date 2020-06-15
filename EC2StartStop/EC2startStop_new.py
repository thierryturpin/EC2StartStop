"""
The EC2 monitor CLI
Monitors all EC2 instances related to an account.
The connect command will invoke the SSH command or the RDP application.
"""

from utils import *

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
    if connect not in global_state.running_instances:
        click.echo(click.style(f'The selected line {connect} is not in a running state', fg='red'))

    ip = global_state.df_ec2_attributes['PrivateIpAddress'][connect]
    name = global_state.df_ec2_attributes['Name'][connect]
    osUser = global_state.df_ec2_attributes['osUser'][connect]
    pemFile = global_state.df_ec2_attributes['pemFile'][connect]

    if sys.platform.startswith('darwin'):
        if global_state.df_ec2_attributes['Platform'][connect] == 'windows':
            cmd = \
                f"""
                open "rdp://full%20address=s:{ip}:3389&domain=s:{global_state.config_data['domain']}&username=s:{global_state.config_data['domainUser']}"
                """
        else:
            banner = f'{SEP}\\nEC2 name: {name}\\nDNS name: \\n{SEP}\\n'
            cmd = \
                f"""
                    osascript <<EOD
                    tell application "Terminal" to do script "ssh {osUser}@{ip} \\
                                                              -i {pemFile} \\
                                                              -t 'clear;tput setaf 2;cat /etc/motd;echo -n \\"{banner}\\" ;tput sgr0; bash -i'"
                """
            cmd += '\n' + 'EOD'

        os.system(cmd)
        click.echo(click.style(cmd, fg='yellow'))

    time.sleep(3)
    main_loop()

@click.command()
@click.option('--start', prompt='Instance to start', type=click.INT, help='Select stopped instance')
@click.argument('conf_file')
def handle_start(start, conf_file):
    if start not in global_state.stopped_instances:
        click.echo(click.style(f'The selected line {start} is not in a stopped state', fg='red'))

    response = get_client('ec2', global_state.config_data['aws_access_key_id'],
                          global_state.config_data['aws_secret_access_key'],
                          global_state.config_data['region']).start_instances(InstanceIds=[global_state.df_ec2_attributes['InstanceId'][start]])

    main_loop()

@click.command()
@click.option('--stop', prompt='Instance to stop', type=click.INT, help='Select started instance')
@click.argument('conf_file')
def handle_stop(stop, conf_file):
    if stop not in global_state.running_instances:
        click.echo(click.style(f'The selected line {stop} is not in a running state', fg='red'))

    response = get_client('ec2', global_state.config_data['aws_access_key_id'],
                          global_state.config_data['aws_secret_access_key'],
                          global_state.config_data['region']).stop_instances(InstanceIds=[global_state.df_ec2_attributes['InstanceId'][stop]])

    main_loop()

def print_instances_grid():
    """
    Print a formatted output of the dataframe
    :return:
    """
    refresh_rate = 60

    global_state.set_ec2_attributes()

    namelen = global_state.df_ec2_attributes.Name.astype(str).map(len).max()
    uptimelen = global_state.df_ec2_attributes.UptimeHours.astype(str).map(len).max()

    click.clear()
    print('Press: CTRL-C for all interactions')

    for cntr, row in global_state.df_ec2_attributes.iterrows():
        # default values
        color = 'white'

        table_line = f"{cntr:3}|{row['Name']:<{namelen}}|{row['EMRNodeType']}|{row['PrivateIpAddress']:<15}|" \
                     f"{row['PublicIp']:<15}|{row['State']:<14}|{row['LocalLaunchTime'].strftime('%d/%m/%y %H:%M')}|" \
                     f"{row['UptimeHours']:{uptimelen}}|{row['InstanceId']:<19}|"

        if row['State'] == 'running':
            color = 'green'
        elif row['State'] in ('pending', 'stopping'):
            color = 'yellow'
            refresh_rate = 3

        click.echo(click.style(table_line, fg=color))

    return refresh_rate


def handle_exit():
    click.clear()
    cover()
    sys.exit()


def handle_user_input():
    """
    Handle all keyboard input
    :return:
    """
    click.echo('p, down, connect, quit, /', nl=False)
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
    else:
        click.echo(click.style('Invalid action', fg='red'))
        time.sleep(1)
        main_loop()


def main_loop():
    """
    The main loop is a separate function, because after input is handled, the main loop needs to be called again
    :return:
    """
    try:
        while True:
            global_state.set_instances()
            time.sleep(print_instances_grid())
    except KeyboardInterrupt:
        handle_user_input()


if __name__ == '__main__':
    cover()
    click_get_config_file.main(standalone_mode=False)
    main_loop()

