import sys
import socket
from timeit import Timer

import asyncssh
import asyncio

import paramiko

from ssh2.session import Session
import concurrent.futures
import uvloop

from netmiko import ConnectHandler
from scrapli.driver.core import AsyncNXOSDriver, AsyncJunosDriver, AsyncEOSDriver

junos_sim = [
    {'host': '127.0.0.1', 'port': 2200, 'user': 'vagrant', 'password': 'vagrant21'},
    {'host': '127.0.0.1', 'port': 2204, 'user': 'vagrant', 'password': 'vagrant21'},
]

cumulus_sim = [
    {'host': '192.168.123.168'},
    {'host': '192.168.123.192'},
    {'host': '192.168.123.196'},
    {'host': '192.168.123.126'},
    {'host': '192.168.123.5'},
    {'host': '192.168.123.98'},
    {'host': '192.168.123.245'},
    {'host': '192.168.123.6'},
    {'host': '192.168.123.219'},
]

eos_sim = [
    {'host': '192.168.121.241'},
    {'host': '192.168.121.2'},
    {'host': '192.168.121.246'},
    {'host': '192.168.121.244'},
    {'host': '192.168.121.125'},
    {'host': '192.168.121.42'},
    {'host': '192.168.121.112'},
    {'host': '192.168.121.37'},
]

nxos_sim = [
    {'host': '10.255.2.45'},
    {'host': '10.255.2.42'},
    {'host': '10.255.2.44'},
    {'host': '10.255.2.43'},
]


def netmiko_ssh(host, port=22, user='vagrant', password='vagrant'):

    global command
    dev_connect = {
        'device_type': 'autodetect',
        'host': host,
        'port': port,
        'username': user,
        'password': password
    }

    net_connect = ConnectHandler(**dev_connect)
    output = net_connect.send_command(command, use_textfsm=False,
                                      expect_string=r'[>#]')
    net_connect.disconnect()
    # print(output)


async def scrapli_ssh(host, port=22, user='vagrant', password='vagrant'):

    global command

    dev_connect = {
        "host": host,
        "auth_username": user,
        "auth_password": password,
        "port": port,
        "auth_strict_key": False,
        "transport": "asyncssh",
    }

    if use_sim == nxos_sim:
        driver = AsyncNXOSDriver
    elif use_sim == eos_sim:
        driver = AsyncEOSDriver
    elif use_sim == junos_sim:
        driver = AsyncJunosDriver

    async with driver(**dev_connect) as conn:
        # Platform drivers will auto-magically handle disabling paging for you
        output = await conn.send_command(command)
        # print(output)


def ssh2_ssh(host, port=22, user='vagrant', password='vagrant'):

    global command

    # Make socket, connect
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    # Initialise
    session = Session()
    session.handshake(sock)

    session.userauth_password(user, password)

    # Public key blob available as identities[0].blob

    # Channel initialise, exec and wait for end
    channel = session.open_session()
    channel.execute(command)
    channel.wait_eof()
    channel.close()
    channel.wait_closed()

    # Print output
    output = b''
    size, data = channel.read()
    while size > 0:
        output += data
        size, data = channel.read()

    # Get exit status
    output = output.decode("utf-8").strip()
    # print(f'{host}, {output}, {channel.get_exit_status()}')


def paramiko_ssh(host, port=22, user='vagrant', password='vagrant'):

    global command

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.MissingHostKeyPolicy())
    client.connect(host, port=port, username=user,
                   password=password, allow_agent=False)
    ssh_in, ssh_out, ssh_err = client.exec_command(command)
    output = ssh_out.read().decode("utf-8").strip()
    client.close()
    # print(f'{host}, {output}, 0')


async def async_ssh(host, port=22, user='vagrant', password='vagrant'):

    global command

    conn = await asyncssh.connect(host, port=port,
                                  username=user, password=password,
                                  client_keys=None,  known_hosts=None)
    output = await conn.run(command)
    # print(f'{host}, {output.stdout.strip()}, {output.exit_status}')
    conn.close()


async def async_run(func, num_hosts=1):
    """Asynchronous version of driving the different async libraries"""
    tasks = []
    for i in range(num_hosts):
        entry = use_sim[i]
        tasks.append(
            func(entry['host'], port=entry.get('port', 22),
                 user=entry.get('user', 'vagrant'),
                 password=entry.get('password', 'vagrant'))
        )

    await asyncio.gather(*tasks)


def sync_run(func, num_hosts=1):
    """Synchronous version of driving the different async libraries"""
    hosts = [entry['host'] for entry in use_sim[:num_hosts]]
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(func, hosts)

    # for i in range(num_hosts):
    #     entry = use_sim[i]
    #     thread = threading.Thread(
    #         target=func,
    #         args=(entry['host'],),
    #         kwargs=({'port': entry.get('port', 22),
    #                  'user': entry.get('user', 'vagrant'),
    #                  'password': entry.get('password', 'vagrant',)}),
    #         daemon=True)
    #     threads.append(thread)
    #     thread.start()

    # for thread in threads:
    #     thread.join()


if __name__ == '__main__':

    if len(sys.argv) < 3:
        print("Usage: ssh_timeit.py <sim_name> <repeat count>")
        sys.exit(1)

    sim_name = sys.argv[1]
    if sim_name not in ['cumulus', 'junos', 'eos', 'nxos']:
        print('sim name has to be one of "cumulus, nxos, junos, eos"')
        sys.exit(1)

    repeat_test = int(sys.argv[2])
    if 100 < repeat_test < 1:
        print("count of repeating test must be between 1-10")
        sys.exit(1)

    namespace = globals()
    use_sim = globals()[sim_name+'_sim']

    if sim_name == 'cumulus':
        command = 'uname -a'
    else:
        command = 'show version'

    print(f'Running single host timing for simulation: {sim_name}')
    uvloop.install()

    t = Timer("""asyncio.run(async_run(async_ssh))""", globals=globals())
    assh_time = t.repeat(repeat=repeat_test, number=1)

    try:
        t = Timer("""sync_run(ssh2_ssh)""", globals=globals())
        ssh2_time = t.repeat(repeat=repeat_test, number=1)
    except Exception:
        print('ssh2 execution failed')
        ssh2_time = [-1]

    t = Timer("""sync_run(paramiko_ssh)""", globals=globals())
    paramiko_time = t.repeat(repeat=repeat_test, number=1)

    t = Timer("""sync_run(netmiko_ssh)""", globals=globals())
    netmiko_time = t.repeat(repeat=repeat_test, number=1)

    if use_sim != cumulus_sim:
        t = Timer("""asyncio.run(async_run(scrapli_ssh))""", globals=globals())
        scrapli_time = t.repeat(repeat=repeat_test, number=1)
    else:
        scrapli_time = [-1]

    print(f'SINGLE HOST RUN(Min of {repeat_test} runs)')
    print('-------------------------------------------')
    print(f'asyncssh: {min(assh_time)}')
    print(f'scrapli: {min(scrapli_time)}')
    print(f'ssh2: {min(ssh2_time)}')
    print(f'paramiko: {min(paramiko_time)}')
    print(f'netmiko: {min(netmiko_time)}')
    print()

    print(f'Running multi-host timing for simulation: {sim_name}, '
          f'{len(use_sim)} hosts')

    t = Timer("""sync_run(paramiko_ssh, len(use_sim))""", globals=globals())
    paramiko_time = t.repeat(repeat=repeat_test, number=3)

    t = Timer("""asyncio.run(async_run(async_ssh, len(use_sim)))""",
              globals=globals())
    assh_time = t.repeat(repeat=repeat_test, number=3)

    t = Timer("""sync_run(ssh2_ssh, len(use_sim))""", globals=globals())
    try:
        ssh2_time = t.repeat(repeat=repeat_test, number=3)
    except Exception:
        print('ssh2 execution failed')
        ssh2_time = [-1]

    t = Timer("""sync_run(netmiko_ssh, len(use_sim))""", globals=globals())
    netmiko_time = t.repeat(repeat=repeat_test, number=3)

    if use_sim != cumulus_sim:
        t = Timer("""asyncio.run(async_run(scrapli_ssh, len(use_sim)))""",
                  globals=globals())
        scrapli_time = t.repeat(repeat=repeat_test, number=3)
    else:
        scrapli_time = [-1]

    print(f'MULTI HOST RUN(Min of {repeat_test} runs)')
    print('------------------------------------------')
    print(f'asyncssh: {min(assh_time)}')
    print(f'scrapli: {min(scrapli_time)}')
    print(f'ssh2: {min(ssh2_time)}')
    print(f'paramiko: {min(paramiko_time)}')
    print(f'netmiko: {min(netmiko_time)}')
