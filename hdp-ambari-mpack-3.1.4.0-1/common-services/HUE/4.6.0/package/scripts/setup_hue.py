#!/usr/bin/env python
# encoding=utf8
import sys, os, pwd, grp, signal, time
reload(sys)
sys.setdefaultencoding('utf8')
from resource_management import *
from subprocess import call
from common import *

def setup_hue():
  import params
  import status_params
  Logger.info("Configure Hue Service")
  # create the pid and log dir
  Directory([params.hue_log_dir, params.hue_pid_dir],
        mode=0755,
        cd_access='a',
        owner=params.hue_user,
        group=params.hue_group,
        create_parents=True
  )
  File([params.hue_log_file, params.hue_server_pid_file],
    mode=0644,
    owner=params.hue_user,
    group=params.hue_group,
    content=''
  )
    
  # these plugin files do not exist in 4.x  
  #Logger.info(format("Creating symlinks /usr/hdp/current/hadoop-client/lib/hue-plugins-{params.hue_version}-SNAPSHOT.jar"))
  #Link("{0}/desktop/libs/hadoop/java-lib/*".format(params.hue_dir),to = "/usr/hdp/current/hadoop-client/lib")
  Execute('find {0} -iname "*.sh" | xargs chmod +x'.format(params.service_packagedir))
  # Create a home directory for solr user on HDFS
  params.HdfsResource(params.hue_hdfs_home_dir,
                type="directory",
                action="create_on_execute",
                owner=params.hue_user,
                mode=0755,
                recursive_chmod=True
  )
  Logger.info(format("Creating {hue_conf_dir}/log.conf file"))
  File(format("{hue_conf_dir}/log.conf"), 
    content = InlineTemplate(params.hue_log_content), 
    owner = params.hue_user
  )
  Logger.info(format("Creating {hue_conf_dir}/hue.ini config file"))
  File(format("{hue_conf_dir}/hue.ini"), 
    content = InlineTemplate(params.hue_ini_content), 
    owner = params.hue_user
  )
  Logger.info(format("Run the script file to add configurations"))
  if params.hue_hdfs_module_enabled == 'Yes':
    add_hdfs_configuration(params.has_ranger_admin, params.security_enabled)
  if params.hue_hbase_module_enabled == 'Yes':
    add_hbase_configuration(params.has_ranger_admin, params.security_enabled)
  if params.hue_hive_module_enabled == 'Yes':
    add_hive_configuration(params.has_ranger_admin, params.security_enabled)
  if params.hue_oozie_module_enabled == 'Yes':
    add_oozie_configuration(params.has_ranger_admin, params.security_enabled)
  if params.hue_spark_module_enabled == 'Yes':
    add_spark_configuration(params.has_ranger_admin, params.security_enabled)

    
    	

