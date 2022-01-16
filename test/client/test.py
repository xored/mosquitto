#!/usr/bin/env python3

import mosq_test_helper
import ptest

tests = [
    #(ports required, 'path'),
    (1, './02-subscribe-argv-errors.py'),
    (1, './02-subscribe-format.py'),
    (1, './02-subscribe-null.py'),
    (1, './02-subscribe-qos1.py'),
    (1, './02-subscribe-verbose.py'),

    (1, './03-publish-argv-errors.py'),
    (1, './03-publish-qos0-empty.py'),
    (1, './03-publish-qos1-properties.py'),
    (1, './03-publish-qos1.py'),
    (2, './03-publish-socks.py'),
    ]

ptest.run_tests(tests)
