# dfhz_hdp_mpack
<h1>DFHz HDP 3.1.4.0 Management Pack for Ambari</h1>

<b><i> </i></b>

#### Install Ambari From MOSGA RPMS:
CENTOS7
<pre>wget -O /etc/yum.repos.d/mosga.repo https://makeopensourcegreatagain.com/repos/centos/7/ambari/2.7.5.0/mosga-ambari.repo
yum install ambari-server ambari-agent -y
ambari-server setup -s
ambari-server start
ambari-agent start</pre>
SUSE12 (work in progress)
<pre>wget -O /etc/zypp/repos.d/mosga-ambari.repo https://makeopensourcegreatagain.com/repos/suse/12/ambari/2.7.5.0/mosga-ambari.repo
zypper install ambari-server ambari-agent -y
ambari-server setup -s
ambari-server start
ambari-agent start</pre>
#### Management Pack Installaion - HDP 3.1.4.0
<pre>ambari-server install-mpack --mpack=https://github.com/steven-dfheinz/dfhz_hdp_mpack/raw/master/hdp-ambari-mpack-3.1.4.0.tar.gz --verbose
ambari-server restart</pre>

#### Management Pack Removal
<pre>ambari-server uninstall-mpack --mpack-name=hdp-ambari-mpack
ambari-server restart</pre>


#### Third Party Services: Hue, Elasticsearch, Flink
- You must install HDP Cluster and disable ambari group user management before installing Third Party Services. See Below.
- You must create Third Party Services Users & Groups (hue,elasticsearch,flink). See Below
- These services are for preview only, they will break HDP Upgrade Paths, and they are not Supported Services.
- Maven 3.6.3 required for building Flink from source.
- Hue & Flink Build times are extremely long due to building from source.  Please be patient during install.


### Disable Ambari User Group Management
<pre>python /var/lib/ambari-server/resources/scripts/configs.py -u admin -p admin -n [CLUSTER_NAME] -l [CLUSTER_FQDN] -t 8080 -a set -c cluster-env -k  ignore_groupsusers_create -v true</pre>
**** be sure to get the correct admin credentials, [CLUSTER_NAME], and [CLUSTER_FQDN] for command above

### Create Third Party Service Users & Groups
<pre>
groupadd hue
useradd -g hue hue
usermod -a -G wheel hue
chown -R hue:hue /home/hue

groupadd flink
useradd -g flink flink
usermod -a -G wheel flink
chown -R flink:flink /home/flink

groupadd elasticsearch
useradd -g elasticsearch elasticsearch
usermod -a -G wheel elasticsearch
chown -R elasticsearch:elasticsearch /home/elasticsearch
</pre>