# dfhz_ddp_mpack
<h1>DFHz Demo Data Platform for Ambari</h1>

<b><i> </i></b>

#### Installation Requirements
- RedHat 7 Centos 7 only.  If you need another operating system reach out privately.
- Please complete a Base Cluster using the Installation Wizard with Zookeeper & Ambari Metrics.  Additional services are then added via Ambari's Add Service Wizard.
- You must install Third Party Tools (hue,elasticsearch,etc) after the Base Cluster is installed and after executing python command to stop ambari managing user groups:
<pre>python /var/lib/ambari-server/resources/scripts/configs.py -u admin -p admin -n [CLUSTER_NAME] -l [CLUSTER_FQDN] -t 8080 -a set -c cluster-env -k  ignore_groupsusers_create -v true</pre>
**** be sure to get the correct admin credentials, [CLUSTER_NAME], and [CLUSTER_FQDN] for command above

#### Install Ambari From MOSGA RPMS:
<pre>wget -O /etc/yum.repos.d/mosga.repo https://makeopensourcegreatagain.com/rpms/mosga.repo
yum install ambari-server ambari-agent -y
ambari-server setup -s
ambari-server start
ambari-agent start</pre>

#### Management Pack Installaion
<pre>ambari-server install-mpack --mpack=https://github.com/steven-dfheinz/dfhz_ddp_mpack/raw/master/ddp-ambari-mpack-0.0.0.4-5.tar.gz --verbose
ambari-server restart</pre>


#### Management Pack Removal
<pre>ambari-server uninstall-mpack --mpack-name=ddp-ambari-mpack
ambari-server restart</pre>


