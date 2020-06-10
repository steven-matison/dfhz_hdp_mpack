#!/usr/bin/env python

'''
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
'''
import socket
import tarfile
import time
import os
import shutil
import glob
from contextlib import closing

from resource_management.libraries.script.script import Script
from resource_management.libraries.resources.hdfs_resource import HdfsResource
from resource_management.libraries.functions.copy_tarball import copy_to_hdfs, get_tarball_paths
from resource_management.libraries.functions import format
from resource_management.core.resources.system import File, Execute
from resource_management.libraries.functions.version import format_stack_version
from resource_management.libraries.functions.stack_features import check_stack_feature
from resource_management.libraries.functions.check_process_status import check_process_status
from resource_management.libraries.functions.constants import StackFeature
from resource_management.libraries.functions.show_logs import show_logs
from resource_management.core.shell import as_sudo
from resource_management.core.exceptions import ComponentIsNotRunning
from resource_management.core.logger import Logger
from common_setup_actions import check_sac_jar

CHECK_COMMAND_TIMEOUT_DEFAULT = 60.0

def make_tarfile(output_filename, source_dirs):
  try:
    os.remove(output_filename)
  except OSError:
    pass
  parent_dir=os.path.dirname(output_filename)
  if not os.path.exists(parent_dir):
    os.makedirs(parent_dir)
  os.chmod(parent_dir, 0711)
  with closing(tarfile.open(output_filename, "w:gz")) as tar:
    for dir in source_dirs:
      for file in os.listdir(dir):
        tar.add(os.path.join(dir,file),arcname=file)
  os.chmod(output_filename, 0644)


def spark_service(name, upgrade_type=None, action=None):
  import params

  if action == 'start':

    check_sac_jar()

    effective_version = params.version if upgrade_type is not None else params.stack_version_formatted
    if effective_version:
      effective_version = format_stack_version(effective_version)

    if name == 'jobhistoryserver' and effective_version and check_stack_feature(StackFeature.SPARK_16PLUS, effective_version):
      # create & copy spark2-hdp-yarn-archive.tar.gz to hdfs
      if not params.sysprep_skip_copy_tarballs_hdfs:
        source_dirs = [params.spark_home + "/jars"]

        # include sac jar and spark-job keytab to archive
        if params.sac_enabled:
          if params.security_enabled:
            shutil.copy(params.atlas_kafka_keytab, source_dirs[0])
            os.chmod(os.path.join(source_dirs[0], os.path.basename(params.atlas_kafka_keytab)), 0440)

          source_dirs.append(params.spark_atlas_jar_dir)


        tmp_archive_file=get_tarball_paths("spark2")[1]
        make_tarfile(tmp_archive_file, source_dirs)
        copy_to_hdfs("spark2", params.user_group, params.hdfs_user, skip=params.sysprep_skip_copy_tarballs_hdfs, replace_existing_files=True)

        if params.sac_enabled and params.security_enabled:
          os.remove(os.path.join(source_dirs[0], os.path.basename(params.atlas_kafka_keytab)))

      # create & copy spark2-hdp-hive-archive.tar.gz to hdfs
      if not params.sysprep_skip_copy_tarballs_hdfs:
        source_dirs = [params.spark_home+"/standalone-metastore"]
        tmp_archive_file=get_tarball_paths("spark2hive")[1]
        make_tarfile(tmp_archive_file, source_dirs)
        copy_to_hdfs("spark2hive", params.user_group, params.hdfs_user, skip=params.sysprep_skip_copy_tarballs_hdfs, replace_existing_files=True)

      # create spark history directory
      params.HdfsResource(params.spark_history_dir,
                          type="directory",
                          action="create_on_execute",
                          owner=params.spark_user,
                          group=params.user_group,
                          mode=0777,
                          recursive_chmod=True
                          )
      params.HdfsResource(None, action="execute")

    if params.security_enabled:
      spark_kinit_cmd = format("{kinit_path_local} -kt {spark_kerberos_keytab} {spark_principal}; ")
      Execute(spark_kinit_cmd, user=params.spark_user)

    # Spark 1.3.1.2.3, and higher, which was included in HDP 2.3, does not have a dependency on Tez, so it does not
    # need to copy the tarball, otherwise, copy it.
    if params.stack_version_formatted and check_stack_feature(StackFeature.TEZ_FOR_SPARK, params.stack_version_formatted):
      resource_created = copy_to_hdfs("tez", params.user_group, params.hdfs_user, skip=params.sysprep_skip_copy_tarballs_hdfs)
      if resource_created:
        params.HdfsResource(None, action="execute")

    if name == 'jobhistoryserver':

      create_catalog_cmd = format("{hive_schematool_bin}/schematool -dbType {hive_metastore_db_type} "
                                    "-createCatalog {default_metastore_catalog} "
                                    "-catalogDescription 'Default catalog, for Spark' -ifNotExists "
                                    "-catalogLocation {default_fs}{spark_warehouse_dir}")

      Execute(create_catalog_cmd,
                user = params.hive_user)

      historyserver_no_op_test = as_sudo(["test", "-f", params.spark_history_server_pid_file]) + " && " + as_sudo(["pgrep", "-F", params.spark_history_server_pid_file])
      try:
        Execute(params.spark_history_server_start,
                user=params.spark_user,
                environment={'JAVA_HOME': params.java_home},
                not_if=historyserver_no_op_test)
      except:
        show_logs(params.spark_log_dir, user=params.spark_user)
        raise

    elif name == 'sparkthriftserver':
      import status_params
      if params.security_enabled:
        hive_kinit_cmd = format("{kinit_path_local} -kt {hive_kerberos_keytab} {hive_kerberos_principal}; ")
        Execute(hive_kinit_cmd, user=params.spark_user)

      thriftserver_no_op_test= as_sudo(["test", "-f", params.spark_thrift_server_pid_file]) + " && " + as_sudo(["pgrep", "-F", params.spark_thrift_server_pid_file])
      try:
        Execute(format('{spark_thrift_server_start} --properties-file {spark_thrift_server_conf_file} {spark_thrift_cmd_opts_properties}'),
                user=params.spark_user,
                environment={'JAVA_HOME': params.java_home},
                not_if=thriftserver_no_op_test
        )
      except:
        show_logs(params.spark_log_dir, user=params.spark_user)
        raise

      hive_connection_created = False
      i = 0
      while i < 15:
        time.sleep(30)
        Logger.info("Check connection to STS is created.")

        beeline_url = ["jdbc:hive2://{fqdn}:{spark_thrift_port}/default"]

        if params.security_enabled:
            beeline_url.append("principal={hive_kerberos_principal}")

        beeline_url.append("transportMode={spark_transport_mode}")

        if params.spark_transport_mode.lower() == 'http':
            beeline_url.append("httpPath={spark_thrift_endpoint}")
            if params.spark_thrift_ssl_enabled:
                beeline_url.append("ssl=true")

        beeline_cmd = os.path.join(params.spark_home, "bin", "beeline")
        cmd = "! %s -u '%s'  -e '' 2>&1| awk '{print}'|grep -i -e 'Connection refused' -e 'Invalid URL' -e 'Error: Could not open'" % \
              (beeline_cmd, format(";".join(beeline_url)))

        try:
          Execute(cmd, user=params.spark_user, path=[beeline_cmd], timeout=CHECK_COMMAND_TIMEOUT_DEFAULT)
          hive_connection_created = True
          Logger.info("Connection to STS is created.")
          break
        except:
          Logger.info("Connection to STS still is not created.")
          pass

        Logger.info("Check STS process status.")
        check_process_status(status_params.spark_thrift_server_pid_file)

        i+=1

      if not hive_connection_created:
        raise ComponentIsNotRunning("Something goes wrong, STS connection was not created but STS process still alive. "
                                    "Potential problems: Hive/YARN doesn't work correctly or too slow. For more information check STS logs.")

  elif action == 'stop':
    if name == 'jobhistoryserver':
      try:
        Execute(format('{spark_history_server_stop}'),
                user=params.spark_user,
                environment={'JAVA_HOME': params.java_home}
        )
      except:
        show_logs(params.spark_log_dir, user=params.spark_user)
        raise
      File(params.spark_history_server_pid_file,
        action="delete"
      )

    elif name == 'sparkthriftserver':
      try:
        Execute(format('{spark_thrift_server_stop}'),
                user=params.spark_user,
                environment={'JAVA_HOME': params.java_home}
        )
      except:
        show_logs(params.spark_log_dir, user=params.spark_user)
        raise
      File(params.spark_thrift_server_pid_file,
        action="delete"
      )


