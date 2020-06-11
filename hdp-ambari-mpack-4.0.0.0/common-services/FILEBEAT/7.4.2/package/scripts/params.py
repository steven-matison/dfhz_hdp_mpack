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

Filebeat Params configurations

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

filebeat_home = '/usr/share/filebeat/'
filebeat_bin = '/usr/share/filebeat/bin/'

conf_dir = "/etc/filebeat"
filebeat_user = config['configurations']['filebeat-env']['filebeat_user']
filebeat_group = config['configurations']['filebeat-env']['filebeat_group']
log_dir = config['configurations']['filebeat-env']['log_dir']
log_level = config['configurations']['filebeat-env']['log_level']
#path_data = config['configurations']['filebeat-env']['path_data']
kibana_url = config['configurations']['filebeat-env']['kibana_url']
parsed = urlparse(kibana_url)
kibana_host = parsed.netloc.split(':')[0]
kibana_port = parsed.netloc.split(':')[1]
logstash_url = config['configurations']['filebeat-env']['logstash_url']
parsed = urlparse(logstash_url)
logstash_host = parsed.netloc.split(':')[0]
logstash_port = parsed.netloc.split(':')[1]

hostname = config['agentLevelParams']['hostname']

java64_home = config['ambariLevelParams']['java_home']
filebeat_yml_template = config['configurations']['filebeat-site']['content']
