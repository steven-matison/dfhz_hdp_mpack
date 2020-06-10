#!/usr/bin/env ambari-python-wrap
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

import imp
import os
import traceback

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STACKS_DIR = os.path.join(SCRIPT_DIR, '../../../3.0/services/HDFS/')
PARENT_FILE = os.path.join(STACKS_DIR, 'service_advisor.py')

try:
  with open(PARENT_FILE, 'rb') as fp:
    service_advisor = imp.load_module('service_advisor', fp, PARENT_FILE, ('.py', 'rb', imp.PY_SOURCE))
except Exception as e:
  traceback.print_exc()
  print "Failed to load parent"

class HDP31HDFSServiceAdvisor(service_advisor.HDFSServiceAdvisor):

  def __init__(self, *args, **kwargs):
    self.as_super = super(HDP31HDFSServiceAdvisor, self)
    self.as_super.__init__(*args, **kwargs)

    self.initialize_logger("HDP31HDFSServiceAdvisor")

    # Always call these methods
    self.modifyMastersWithMultipleInstances()
    self.modifyCardinalitiesDict()
    self.modifyHeapSizeProperties()
    self.modifyNotValuableComponents()
    self.modifyComponentsNotPreferableOnServer()
    self.modifyComponentLayoutSchemes()

  def modifyMastersWithMultipleInstances(self):
    """
    Modify the set of masters with multiple instances.
    Must be overridden in child class.
    """

    pass

  def modifyCardinalitiesDict(self):
    """
    Modify the dictionary of cardinalities.
    Must be overridden in child class.
    """

    pass

  def modifyHeapSizeProperties(self):
    """
    Modify the dictionary of heap size properties.
    Must be overridden in child class.
    """

    self.heap_size_properties = {"NAMENODE":
                                  [{"config-name": "hadoop-env",
                                    "property": "namenode_heapsize",
                                    "default": "1024m"}],
                                 "SECONDARY_NAMENODE":
                                  [{"config-name": "hadoop-env",
                                    "property": "namenode_heapsize",
                                    "default": "1024m"}],
                                 "DATANODE":
                                  [{"config-name": "hadoop-env",
                                    "property": "dtnode_heapsize",
                                    "default": "1024m"}]
                                }

  def modifyNotValuableComponents(self):
    """
    Modify the set of components whose host assignment is based on other services.
    Must be overridden in child class.
    """

    self.notValuableComponents |= set(['JOURNALNODE', 'ZKFC'])

  def modifyComponentsNotPreferableOnServer(self):
    """
    Modify the set of components that are not preferable on the server.
    Must be overridden in child class.
    """

    pass

  def modifyComponentLayoutSchemes(self):
    """
    Modify layout scheme dictionaries for components.
    The scheme dictionary basically maps the number of hosts to
    host index where component should exist.
    Must be overridden in child class.
    """

    self.componentLayoutSchemes.update({
      'NAMENODE': {"else": 0},
      'SECONDARY_NAMENODE': {"else": 1}
    })

  def getServiceComponentLayoutValidations(self, services, hosts):
    """
    Get a list of errors.
    Must be overridden in child class.
    """

    # HDFS allows NameNode and Secondary NameNode to be on the same host
    return self.getServiceComponentCardinalityValidations(services, hosts, "HDFS")

  def getServiceConfigurationRecommendations(self, configurations, clusterData, services, hosts):
    super(HDP31HDFSServiceAdvisor, self).getServiceConfigurationRecommendations(configurations, clusterData, services, hosts)

    recommender = HDP31HDFSRecommender()
    recommender.recommendHDFSConfigurationsFromHDP31(configurations, clusterData, services, hosts)

class HDP31HDFSRecommender(service_advisor.ServiceAdvisor):
  """
  HDFS Recommender suggests properties when adding the service for the first time or modifying configs via the UI.
  """

  def __init__(self, *args, **kwargs):
    self.as_super = super(HDP31HDFSRecommender, self)
    self.as_super.__init__(*args, **kwargs)

  def recommendHDFSConfigurationsFromHDP31(self, configurations, clusterData, services, hosts):
    putHdfsSiteProperty = self.putProperty(configurations, "hdfs-site", services)

    ranger_hdfs_plugin_enabled = False

    if 'ranger-hdfs-plugin-properties' in configurations and 'ranger-hdfs-plugin-enabled' in configurations['ranger-hdfs-plugin-properties']['properties']:
      ranger_hdfs_plugin_enabled = (configurations['ranger-hdfs-plugin-properties']['properties']['ranger-hdfs-plugin-enabled'].lower() == 'Yes'.lower())
    elif 'ranger-hdfs-plugin-properties' in services['configurations'] and 'ranger-hdfs-plugin-enabled' in services['configurations']['ranger-hdfs-plugin-properties']['properties']:
      ranger_hdfs_plugin_enabled = (services['configurations']['ranger-hdfs-plugin-properties']['properties']['ranger-hdfs-plugin-enabled'].lower() == 'Yes'.lower())

    if ranger_hdfs_plugin_enabled:
      putHdfsSiteProperty('dfs.permissions.ContentSummary.subAccess', 'true')
    else:
      putHdfsSiteProperty('dfs.permissions.ContentSummary.subAccess', 'false')
