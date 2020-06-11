#!/usr/bin/env python
"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Logstash Params configurations

"""
# encoding=utf8
import sys
reload(sys)
sys.setdefaultencoding('utf8')

from urlparse import urlparse

from resource_management.libraries.functions import format
from resource_management.libraries.script import Script

# server configurations
config = Script.get_config()

logstash_home = '/usr/share/logstash/'
logstash_bin = '/usr/share/logstash/bin/'

conf_dir = "/etc/logstash"
logstash_user = config['configurations']['logstash-env']['logstash_user']
logstash_group = config['configurations']['logstash-env']['logstash_group']
log_dir = config['configurations']['logstash-env']['log_dir']
log_level = config['configurations']['logstash-env']['log_level']
path_data = config['configurations']['logstash-env']['path_data']
es_url = config['configurations']['logstash-env']['es_url']
parsed = urlparse(es_url)
es_host = parsed.netloc.split(':')[0]
es_port = parsed.netloc.split(':')[1]

hostname = config['agentLevelParams']['hostname']

java64_home = config['ambariLevelParams']['java_home']
logstash_yml_template = config['configurations']['logstash-site']['content']
logstash_input_template = config['configurations']['logstash-site']['content_input']
input_port = config['configurations']['logstash-env']['input_port']
logstash_output_template = config['configurations']['logstash-site']['content_output']
logstash_filter_template = config['configurations']['logstash-site']['content_filter']

heap_size = config['configurations']['logstash-jvm-options']['heap_size']
jvm_options_template = config['configurations']['logstash-jvm-options']['content']
