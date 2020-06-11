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
"""
# encoding=utf8
import sys
reload(sys)
sys.setdefaultencoding('utf8')

from resource_management.core.logger import Logger
from resource_management.core.resources.system import Directory
from resource_management.core.resources.system import Execute
from resource_management.core.resources.system import File
from resource_management.core.source import InlineTemplate
from resource_management.libraries.functions.format import format as ambari_format
from resource_management.libraries.script import Script

from common import service_check

class Logstash(Script):

    def install(self, env):
        import params
        env.set_params(params)
        Logger.info("Installing Logstash")
        self.install_packages(env)

    def configure(self, env, upgrade_type=None, config_dir=None):
        import params
        env.set_params(params)
        Logger.info("Configuring Logstash")

        directories = [params.log_dir, params.conf_dir]
        Directory(directories,
                  mode=0755,
                  owner=params.logstash_user,
                  group=params.logstash_user
                  )

        File("{0}/logstash.yml".format(params.conf_dir),
             owner=params.logstash_user,
             content=InlineTemplate(params.logstash_yml_template)
             )

   	File("{0}/jvm.options".format(params.conf_dir),
             content=InlineTemplate(params.jvm_options_template),
             owner=params.logstash_user,
             group=params.logstash_group)

        File("{0}/conf.d/02-beats-input.conf".format(params.conf_dir),
             owner=params.logstash_user,
             content=InlineTemplate(params.logstash_input_template)
             )

        File("{0}/conf.d/30-elasticsearch-output.conf".format(params.conf_dir),
             owner=params.logstash_user,
             content=InlineTemplate(params.logstash_output_template)
             )
        File("{0}/conf.d/10-filebeat-filter.conf".format(params.conf_dir),
             owner=params.logstash_user,
             content=InlineTemplate(params.logstash_filter_template)
             )

    def stop(self, env, upgrade_type=None):
        import params
        env.set_params(params)
        Logger.info("Stopping Logstash")
        Execute("service logstash stop")

    def start(self, env, upgrade_type=None):
        import params
        env.set_params(params)
        self.configure(env)
        Logger.info("Starting Logstash")
        Execute("service logstash start")

    def restart(self, env):
        import params
        env.set_params(params)
        self.configure(env)
        Logger.info("Restarting Logstash")
        Execute("service logstash restart")

    def status(self, env):
        import params
        env.set_params(params)
        Logger.info('Status check Logstash')
        service_check("service logstash status", user=params.logstash_user, label="Logstash")

if __name__ == "__main__":
    Logstash().execute()
