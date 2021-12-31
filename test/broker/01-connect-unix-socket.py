#!/usr/bin/env python3

# Test whether connections to a unix socket work

from mosq_test_helper import *

def start_broker(filename):
    cmd = ['../../src/mosquitto', '-v', '-c', filename]

    if os.environ.get('MOSQ_USE_VALGRIND') is not None:
        logfile = filename+'.'+str(vg_index)+'.vglog'
        if os.environ.get('MOSQ_USE_VALGRIND') == 'callgrind':
            cmd = ['valgrind', '-q', '--tool=callgrind', '--log-file='+logfile] + cmd
        elif os.environ.get('MOSQ_USE_VALGRIND') == 'massif':
            cmd = ['valgrind', '-q', '--tool=massif', '--log-file='+logfile] + cmd
        else:
            cmd = ['valgrind', '-q', '--trace-children=yes', '--leak-check=full', '--show-leak-kinds=all', '--log-file='+logfile] + cmd

    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def write_config(filename, port):
    with open(filename, 'w') as f:
        f.write("listener 0 %d.sock\n" % (port))
        f.write("allow_anonymous true\n")

def do_test():
    rc = 1

    connect_packet = mosq_test.gen_connect("unix-socket")
    connack_packet = mosq_test.gen_connack(rc=0)

    port = mosq_test.get_port()
    conf_file = os.path.basename(__file__).replace('.py', '.conf')
    write_config(conf_file, port)
    broker = start_broker(filename=os.path.basename(__file__))

    try:
        sock = mosq_test.do_client_connect_unix(connect_packet, connack_packet, path=f"{port}.sock")
        sock.close()

        rc = 0
    except mosq_test.TestError:
        pass
    except Exception as err:
        print(err)
    finally:
        broker.terminate()
        broker.wait()
        os.remove(conf_file)
        os.remove(f"{port}.sock")
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            exit(rc)

do_test()
exit(0)
