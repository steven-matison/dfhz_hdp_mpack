#!/usr/bin/python
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
import os

from urlparse import urlparse
from resource_management.core.resources.system import Execute
from resource_management.libraries.resources.xml_config import XmlConfig
from resource_management.libraries.functions import format
from resource_management.libraries.resources.properties_file import PropertiesFile
from resource_management.core.logger import Logger


def create_atlas_configs():
    import params
    if params.sac_enabled:
        atlas_application_properties = params.application_properties
        atlas_application_properties_override = params.application_properties_override
        atlas_application_properties_yarn = params.application_properties_yarn
        for property_name in params.atlas_application_properties_to_include:
            if property_name in atlas_application_properties and not property_name in atlas_application_properties_override:
                atlas_application_properties_override[property_name] = atlas_application_properties[property_name]

        if params.security_enabled:
          for property_name in params.secure_atlas_application_properties_to_include.keys():
            if not property_name in atlas_application_properties_override:
              atlas_application_properties_override[property_name] = params.secure_atlas_application_properties_to_include[property_name]

        PropertiesFile(params.atlas_properties_path,
                       properties = atlas_application_properties_override,
                       mode=0644,
                       owner=params.spark_user,
                       group=params.user_group
                       )


        atlas_application_properties_override_copy = atlas_application_properties_override.copy()
        if params.security_enabled:
            atlas_application_properties_override_copy.pop("atlas.jaas.KafkaClient.option.keyTab")

        atlas_application_properties_override_copy.update(atlas_application_properties_yarn)
        atlas_application_properties_yarn = atlas_application_properties_override_copy

        PropertiesFile(params.atlas_properties_for_yarn_path,
                       properties = atlas_application_properties_yarn,
                       mode=0644,
                       owner=params.spark_user,
                       group=params.user_group
                       )

def check_sac_jar():
    import params

    if params.sac_enabled:
        sac_jar_exists = False
        if os.path.isdir(params.spark_atlas_jar_dir):
            for file in os.listdir(params.spark_atlas_jar_dir):
                if str(file).startswith("spark-atlas-connector-assembly"):
                    sac_jar_exists = True

        if not sac_jar_exists:
            raise Exception("Please check that SAC jar is available in " + params.spark_atlas_jar_dir)
        else:
            Logger.info("SAC jar is available.")
