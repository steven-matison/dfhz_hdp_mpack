# dfhz_hdp_mpack
<h1>HDP 3.1.4.0 Management Pack for Ambari</h1>

<b><i> </i></b>

#### Install Ambari From MOSGA RPMS:
CENTOS7
<pre>wget -O /etc/yum.repos.d/mosga.repo https://makeopensourcegreatagain.com/repos/centos/7/ambari/2.7.5.0/mosga-ambari.repo
yum install ambari-server ambari-agent -y
ambari-server setup -s
ambari-server start
ambari-agent start</pre>

#### Management Pack Installaion - HDP 3.1.4.0
<pre>ambari-server install-mpack --mpack=https://github.com/steven-matison/dfhz_hdp_mpack/raw/master/hdp-ambari-mpack-3.1.4.0.tar.gz --verbose
ambari-server restart</pre>

#### Management Pack Removal
<pre>ambari-server uninstall-mpack --mpack-name=hdp-ambari-mpack
ambari-server restart</pre>


