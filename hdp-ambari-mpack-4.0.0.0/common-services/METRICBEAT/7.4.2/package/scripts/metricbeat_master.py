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

class Metricbeat(Script):

    def install(self, env):
        import params
        env.set_params(params)
        Logger.info("Installing Metricbeat")
        self.install_packages(env)

    def configure(self, env, upgrade_type=None, config_dir=None):
        import params
        env.set_params(params)
        Logger.info("Configuring Metricbeat")

        directories = [params.log_dir, params.conf_dir]
        Directory(directories,
                  mode=0755,
                  owner=params.metricbeat_user,
                  group=params.metricbeat_user
                  )

        File("{0}/metricbeat.yml".format(params.conf_dir),
             owner=params.metricbeat_user,
             content=InlineTemplate(params.metricbeat_yml_template)
             )

    def stop(self, env, upgrade_type=None):
        import params
        env.set_params(params)
        Logger.info("Stopping Metricbeat")
        Execute("service metricbeat stop")

    def start(self, env, upgrade_type=None):
        import params
        env.set_params(params)
        self.configure(env)
        Logger.info("Starting Metricbeat")
        Execute("service metricbeat start")

    def restart(self, env):
        import params
        env.set_params(params)
        self.configure(env)
        Logger.info("Restarting Metricbeat")
        Execute("service metricbeat restart")

    def status(self, env):
        import params
        env.set_params(params)
        Logger.info('Status check Metricbeat')
        service_check("service metricbeat status", user=params.metricbeat_user, label="Metricbeat")

if __name__ == "__main__":
    Metricbeat().execute()
