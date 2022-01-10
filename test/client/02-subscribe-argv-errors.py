#!/usr/bin/env python3

#

from mosq_test_helper import *

def do_test(args, stderr_expected, rc_expected):
    rc = 1

    port = mosq_test.get_port()

    env = {
            'LD_LIBRARY_PATH':'../../lib',
            'XDG_CONFIG_HOME':'/tmp/missing'
            }
    cmd = ['../../client/mosquitto_sub'] + args

    sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    sub.wait()
    (stdo, stde) = sub.communicate()
    if sub.returncode != rc_expected:
        raise mosq_test.TestError(sub.returncode)
    if stderr_expected is not None and stde.decode('utf-8') != stderr_expected:
        raise mosq_test.TestError(stde)


if __name__ == '__main__':
    helps = "\nUse 'mosquitto_sub --help' to see usage.\n"

    # Usage, ignore actual text though.
    do_test(['--help'], None, 1)

    # Missing args
    do_test(['-A'], "Error: -A argument given but no address specified.\n\n" + helps, 1)
    do_test(['--cafile'], "Error: --cafile argument given but no file specified.\n\n" + helps, 1)
    do_test(['--capath'], "Error: --capath argument given but no directory specified.\n\n" + helps, 1)
    do_test(['--cert'], "Error: --cert argument given but no file specified.\n\n" + helps, 1)
    do_test(['--ciphers'], "Error: --ciphers argument given but no ciphers specified.\n\n" + helps, 1)
    do_test(['-h'], "Error: -h argument given but no host specified.\n\n" + helps, 1)
    do_test(['-i'], "Error: -i argument given but no id specified.\n\n" + helps, 1)
    do_test(['-I'], "Error: -I argument given but no id prefix specified.\n\n" + helps, 1)
    do_test(['-k'], "Error: -k argument given but no keepalive specified.\n\n" + helps, 1)
    do_test(['--key'], "Error: --key argument given but no file specified.\n\n" + helps, 1)
    do_test(['--keyform'], "Error: --keyform argument given but no keyform specified.\n\n" + helps, 1)
    do_test(['-L'], "Error: -L argument given but no URL specified.\n\n" + helps, 1)
    do_test(['-M'], "Error: -M argument given but max_inflight not specified.\n\n" + helps, 1)
    do_test(['-o'], "Error: -o argument given but no options file specified.\n\n" + helps, 1)
    do_test(['-p'], "Error: -p argument given but no port specified.\n\n" + helps, 1)
    do_test(['-P'], "Error: -P argument given but no password specified.\n\n" + helps, 1)
    do_test(['--proxy'], "Error: --proxy argument given but no proxy url specified.\n\n" + helps, 1)
    do_test(['--psk'], "Error: --psk argument given but no key specified.\n\n" + helps, 1)
    do_test(['--psk-identity'], "Error: --psk-identity argument given but no identity specified.\n\n" + helps, 1)
    do_test(['-q'], "Error: -q argument given but no QoS specified.\n\n" + helps, 1)
    do_test(['-t'], "Error: -t argument given but no topic specified.\n\n" + helps, 1)
    do_test(['--tls-alpn'], "Error: --tls-alpn argument given but no protocol specified.\n\n" + helps, 1)
    do_test(['--tls-engine'], "Error: --tls-engine argument given but no engine_id specified.\n\n" + helps, 1)
    do_test(['--tls-engine-kpass-sha1'], "Error: --tls-engine-kpass-sha1 argument given but no kpass sha1 specified.\n\n" + helps, 1)
    do_test(['--tls-version'], "Error: --tls-version argument given but no version specified.\n\n" + helps, 1)
    do_test(['-u'], "Error: -u argument given but no username specified.\n\n" + helps, 1)
    do_test(['--unix'], "Error: --unix argument given but no socket path specified.\n\n" + helps, 1)
    do_test(['-V'], "Error: --protocol-version argument given but no version specified.\n\n" + helps, 1)
    do_test(['--will-payload'], "Error: --will-payload argument given but no will payload specified.\n\n" + helps, 1)
    do_test(['--will-qos'], "Error: --will-qos argument given but no will QoS specified.\n\n" + helps, 1)
    do_test(['--will-topic'], "Error: --will-topic argument given but no will topic specified.\n\n" + helps, 1)
    do_test(['-x'], "Error: -x argument given but no session expiry interval specified.\n\n" + helps, 1)

    do_test(['--will-payload', 'payload'], "Error: Will payload given, but no will topic given.\n" + helps, 1)

    # Invalid combinations
    do_test(['-i', 'id', '-I', 'id-prefix'], "Error: -i and -I argument cannot be used together.\n\n" + helps, 1)
    do_test(['-I', 'id-prefix', '-i', 'id'], "Error: -i and -I argument cannot be used together.\n\n" + helps, 1)

    # Invalid output format
    do_test(['-F', '%'], "Error: Incomplete format specifier.\n" + helps, 1)
    do_test(['-F', '%0'], "Error: Incomplete format specifier.\n" + helps, 1)
    do_test(['-F', '%-'], "Error: Incomplete format specifier.\n" + helps, 1)
    do_test(['-F', '%1'], "Error: Incomplete format specifier.\n" + helps, 1)
    do_test(['-F', '%.'], "Error: Incomplete format specifier.\n" + helps, 1)
    do_test(['-F', '%.1'], "Error: Incomplete format specifier.\n" + helps, 1)
    do_test(['-F', '%Z'], "Error: Invalid format specifier 'Z'.\n" + helps, 1)
    do_test(['-F', '@'], "Error: Incomplete format specifier.\n" + helps, 1)
    do_test(['-F', '\\'], "Error: Incomplete escape specifier.\n" + helps, 1)
    do_test(['-F', '\\Z'], "Error: Invalid escape specifier 'Z'.\n" + helps, 1)

    # Invalid values
    do_test(['-k', '-1'], "Error: Invalid keepalive given, it must be between 5 and 65535 inclusive.\n\n" + helps, 1)
    do_test(['-k', '65536'], "Error: Invalid keepalive given, it must be between 5 and 65535 inclusive.\n\n" + helps, 1)
    do_test(['-M', '0'], "Error: Maximum inflight messages must be greater than 0.\n\n" + helps, 1)
    do_test(['-p', '-1'], "Error: Invalid port given: -1\n" + helps, 1)
    do_test(['-p', '65536'], "Error: Invalid port given: 65536\n" + helps, 1)
    do_test(['-q', '-1'], "Error: Invalid QoS given: -1\n" + helps, 1)
    do_test(['-q', '3'], "Error: Invalid QoS given: 3\n" + helps, 1)

    # Unknown options
    do_test(['--unknown'], "Error: Unknown option '--unknown'.\n" + helps, 1)
