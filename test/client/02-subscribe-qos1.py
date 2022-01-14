#!/usr/bin/env python3

#

from mosq_test_helper import *

def do_test(start_broker, proto_ver):
    rc = 1

    port = mosq_test.get_port()

    if proto_ver == 5:
        V = 'mqttv5'
    elif proto_ver == 4:
        V = 'mqttv311'
    else:
        V = 'mqttv31'

    env = {
            'LD_LIBRARY_PATH':'../../lib',
            'XDG_CONFIG_HOME':'/tmp/missing'
            }
    cmd = ['../../client/mosquitto_sub',
            '-p', str(port),
            '-q', '1',
            '-t', '02/sub/qos1/test',
            '-V', V,
            '-C', '1'
            ]

    payload = "message"
    publish_packet_s = mosq_test.gen_publish("02/sub/qos1/test", qos=1, mid=1, payload=payload, proto_ver=proto_ver)
    publish_packet_r = mosq_test.gen_publish("02/sub/qos1/test", qos=1, mid=2, payload=payload, proto_ver=proto_ver)
    puback_packet_s = mosq_test.gen_puback(1, proto_ver=proto_ver)
    puback_packet_r = mosq_test.gen_puback(2, proto_ver=proto_ver)

    if start_broker:
        broker = mosq_test.start_broker(filename=os.path.basename(__file__), port=port)

    try:
        sock = mosq_test.pub_helper(port=port, proto_ver=proto_ver)

        sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        time.sleep(0.5)
        sock.send(publish_packet_s)
        mosq_test.expect_packet(sock, "puback", puback_packet_s)
        sub.wait()
        (stdo, stde) = sub.communicate()
        if stdo.decode('utf-8') == payload + '\n':
            rc = 0
        sock.close()
    except mosq_test.TestError:
        pass
    except Exception as e:
        print(e)
    finally:
        if start_broker:
            broker.terminate()
            broker.wait()
            (stdo, stde) = broker.communicate()
            if rc:
                print(stde.decode('utf-8'))
                print("proto_ver=%d" % (proto_ver))
                exit(rc)
        else:
            return rc


def all_tests(start_broker=False):
    rc = do_test(start_broker, proto_ver=3)
    if rc:
        return rc;
    rc = do_test(start_broker, proto_ver=4)
    if rc:
        return rc;
    rc = do_test(start_broker, proto_ver=5)
    if rc:
        return rc;
    return 0

if __name__ == '__main__':
    all_tests(True)
