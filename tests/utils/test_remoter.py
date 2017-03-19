#!/usr/bin/env python
# *-*coding: UTF-8 *-*
#######################################
#File Name: test_remoter.py
#Created Time: 2017-03-19 16:17:57
#Author: hoyping@163.com
#######################################

import os
import unittest
from ...utils import remoter

class RemoteTestCase(unittest.TestCase):
    def setUp(self):
        self.data_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data')
        self.remoter = remoter.Remote('localhost', 'huyiping','hyp121')

    def testSendFile(self):
        local_path = os.path.join(self.data_path, 'sendfile')
        remote_path = os.path.join(self.data_path, 'sendfile_remote')
        self.remoter.send_files(local_path, remote_path)


    def tearDown(self):
        pass
