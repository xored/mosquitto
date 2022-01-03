#!/usr/bin/env python3

# Test whether config parse errors are handled

from mosq_test_helper import *

def start_broker(filename):
    if filename is not None:
        cmd = ['../../src/mosquitto', '-v', '-c', filename]
    else:
        cmd = ['../../src/mosquitto', '-h']

    if os.environ.get('MOSQ_USE_VALGRIND') is not None:
        logfile = filename+'.'+str(vg_index)+'.vglog'
        if os.environ.get('MOSQ_USE_VALGRIND') == 'callgrind':
            cmd = ['valgrind', '-q', '--tool=callgrind', '--log-file='+logfile] + cmd
        elif os.environ.get('MOSQ_USE_VALGRIND') == 'massif':
            cmd = ['valgrind', '-q', '--tool=massif', '--log-file='+logfile] + cmd
        else:
            cmd = ['valgrind', '-q', '--trace-children=yes', '--leak-check=full', '--show-leak-kinds=all', '--log-file='+logfile] + cmd

    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def write_config(filename, port, config_str):
    with open(filename, 'w') as f:
        f.write(f"{config_str}")


def do_test(config_str, rc_expected):
    rc = 1
    port = mosq_test.get_port()

    if config_str is not None:
        conf_file = os.path.basename(__file__).replace('.py', '.conf')
        write_config(conf_file, port, config_str)
    else:
        conf_file = None

    try:
        broker = start_broker(conf_file)
        broker.wait(timeout=1)

        if broker.returncode == rc_expected:
            rc = 0
    except mosq_test.TestError:
        pass
    except subprocess.TimeoutExpired:
        broker.terminate()
    except Exception as e:
        print(e)
    finally:
        if conf_file is not None:
            os.remove(conf_file)
        (stdo, stde) = broker.communicate()
        if rc:
            print(stde.decode('utf-8'))
            print(config_str)
            exit(rc)


do_test(None, 3) # Print usage

do_test("unknown_option unknown\n", 3)

do_test("user\n", 3) # Empty string, no space
do_test("user \n", 3) # Empty string, single space
do_test("user  \n", 3) # Empty string, double space
do_test("pid_file /tmp/pid\npid_file /tmp/pid\n", 3) # Duplicate string

do_test("memory_limit\n", 3) # Empty ssize_t

do_test("accept_protocol_versions 3\n", 3) # Missing listener
do_test("listener 1888\naccept_protocol_versions\n", 3) # Empty value

do_test("allow_anonymous\n", 3) # Empty bool
do_test("allow_anonymous falst\n", 3) # Invalid bool

do_test("autosave_interval\n", 3) # Empty int
#do_test("autosave_interval string\n", 3) # Invalid int

do_test("listener\n", 3) # Empty listener
do_test("mount_point test/\n", 3) # Missing listener config
do_test("listener 1888\nmount_point test/+/\n", 3) # Wildcard in mount point.
do_test("listener 1888\nprotocol\n", 3) # Empty proto
do_test("listener 1888\nprotocol test\n", 3) # Invalid proto

do_test("plugin_opt_inval string\n", 3) # plugin_opt_ without plugin
do_test("plugin c/auth_plugin.so\nplugin_opt_ string\n", 3) # Incomplete plugin_opt_
do_test("plugin c/auth_plugin.so\nplugin_opt_test\n", 3) # Empty plugin_opt_

do_test("bridge_attempt_unsubscribe true\n", 3) # Missing bridge config
do_test("bridge_cafile string\n", 3) # Missing bridge config
do_test("bridge_alpn string\n", 3) # Missing bridge config
do_test("bridge_ciphers string\n", 3) # Missing bridge config
do_test("bridge_ciphers_tls1.3 string\n", 3) # Missing bridge config
do_test("bridge_bind_address string\n", 3) # Missing bridge config
do_test("bridge_capath string\n", 3) # Missing bridge config
do_test("bridge_certfile string\n", 3) # Missing bridge config
do_test("bridge_identity string\n", 3) # Missing bridge config
do_test("bridge_insecure true\n", 3) # Missing bridge config
do_test("bridge_require_oscp true\n", 3) # Missing bridge config
do_test("bridge_max_packet_size 1000\n", 3) # Missing bridge config
do_test("bridge_max_topic_alias 1000\n", 3) # Missing bridge config
do_test("bridge_outgoing_retain false\n", 3) # Missing bridge config
do_test("bridge_keyfile string\n", 3) # Missing bridge config
do_test("bridge_protocol_version string\n", 3) # Missing bridge config
do_test("bridge_psk string\n", 3) # Missing bridge config
do_test("bridge_receive_maximum 10\n", 3) # Missing bridge config
do_test("bridge_reload_type string\n", 3) # Missing bridge config
do_test("bridge_session_expiry_interval 10000\n", 3) # Missing bridge config
do_test("bridge_tcp_keepalive 10000\n", 3) # Missing bridge config
do_test("bridge_tcp_user_timeout 10000\n", 3) # Missing bridge config
do_test("bridge_tls_version string\n", 3) # Missing bridge config
do_test("local_clientid str\n", 3) # Missing bridge config
do_test("local_password str\n", 3) # Missing bridge config
do_test("local_username str\n", 3) # Missing bridge config
do_test("notifications true\n", 3) # Missing bridge config
do_test("notifications_local_only true\n", 3) # Missing bridge config
do_test("notification_topic true\n", 3) # Missing bridge config
do_test("password pw\n", 3) # Missing bridge config
do_test("remote_password pw\n", 3) # Missing bridge config
do_test("restart_timeout 10\n", 3) # Missing bridge config
do_test("round_robin true\n", 3) # Missing bridge config
do_test("start_type lazy\n", 3) # Missing bridge config
do_test("threshold 10\n", 3) # Missing bridge config
do_test("topic topic/10\n", 3) # Missing bridge config
do_test("try_private true\n", 3) # Missing bridge config
do_test("username un\n", 3) # Missing bridge config

do_test("maximum_qos 3\n", 3) # Invalid maximum qos
do_test("maximum_qos -1\n", 3) # Invalid maximum qos

do_test("max_inflight_messages 65536\n", 3) # Invalid value

do_test("max_keepalive 65536\n", 3) # Invalid value
do_test("max_keepalive -1\n", 3) # Invalid value

do_test("max_topic_alias 65536\n", 3) # Invalid value
do_test("max_topic_alias -1\n", 3) # Invalid value

do_test("max_topic_alias_broker 65536\n", 3) # Invalid value
do_test("max_topic_alias_broker -1\n", 3) # Invalid value

do_test("websockets_headers_size 65536\n", 3) # Invalid value
do_test("websockets_headers_size -1\n", 3) # Invalid value

do_test("memory_limit -1\n", 3) # Invalid value

do_test("sys_interval -1\n", 3) # Invalid value
do_test("sys_interval 65536\n", 3) # Invalid value

do_test("listener 1888\ncertfile\n", 3) # empty certfile
do_test("listener 1888\nkeyfile\n", 3) # empty keyfile

do_test("listener 1888\ncertfile ./16-config-parse-errors.py\nkeyfile ../ssl/server.key\n", 1) # invalid certfile
do_test("listener 1888\ncertfile ../ssl/server.crt\nkeyfile ./16-config-parse-errors.py\n", 1) # invalid keyfile
do_test("listener 1888\ncertfile ../ssl/server.crt\nkeyfile ../ssl/client.key\n", 1) # mismatched certfile / keyfile

do_test("listener 1888\ncertfile ../ssl/server.crt\nkeyfile ../ssl/server.key\ntls_version invalid\n", 1) # invalid tls_version

do_test("listener 1888\ncertfile ../ssl/server.crt\nkeyfile ../ssl/server.key\ncrlfile invalid\n", 1) # missing crl file
do_test("listener 1888\ncertfile ../ssl/server.crt\nkeyfile ../ssl/server.key\ndhparamfile invalid\n", 1) # missing dh param file
do_test("listener 1888\ncertfile ../ssl/server.crt\nkeyfile ../ssl/server.key\ndhparamfile ./16-config-parse-errors.py\n", 1) # invalid dh param file

do_test("listener 1888\ncertfile ../ssl/server.crt\nkeyfile ../ssl/server.key\nciphers invalid\n", 1) # invalid ciphers
do_test("listener 1888\ncertfile ../ssl/server.crt\nkeyfile ../ssl/server.key\nciphers_tls1.3 invalid\n", 1) # invalid ciphers_tls1.3


exit(0)
