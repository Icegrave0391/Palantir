# System Auditing Setup

## Install Auditbeat developed by [Elastic](https://www.elastic.co/beats/auditbeat):

Note: auditbeat depends on auditd.
```bash
sudo apt install auditd
sudo apt install auditbeat
sudo service auditd stop
sudo service auditbeat stop
sudo systemctl disable auditd
sudo systemctl disable auditbeat
```