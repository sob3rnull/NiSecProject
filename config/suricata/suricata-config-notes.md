# Suricata configuration notes

> **This file is documentation only — nothing reads it at runtime.**
> It was previously named `suricata.yaml.overrides`, which wrongly implied
> it was applied automatically. The actual changes are made by
> `provision/monitored-server.sh`.

# This file DOCUMENTS the changes the provisioner makes to the stock
# /etc/suricata/suricata.yaml. Suricata reads one monolithic YAML, so
# rather than ship a whole 2000-line file we patch these keys in place
# (see provision/monitored-server.sh). If you edit by hand, mirror these.
#
# 1) Define our lab as HOME_NET so "inbound" is judged correctly:
#
#      vars:
#        address-groups:
#          HOME_NET: "[192.168.56.0/24]"
#          EXTERNAL_NET: "!$HOME_NET"
#
# 2) Sniff the host-only interface (auto-detected; usually eth1):
#
#      af-packet:
#        - interface: eth1
#          cluster-id: 99
#          cluster-type: cluster_flow
#          defrag: yes
#
# 3) Keep JSON alerting on — this is the file Wazuh reads:
#
#      outputs:
#        - eve-log:
#            enabled: yes
#            filetype: regular
#            filename: /var/log/suricata/eve.json
#            types:
#              - alert
#              - anomaly
#              - http
#              - dns
#              - flow
#
# 4) Load the community + our local rules:
#
#      default-rule-path: /var/lib/suricata/rules
#      rule-files:
#        - suricata.rules      # from suricata-update (ET Open)
#        - local.rules         # our custom threshold rules
#
# After editing: sudo suricata -T -c /etc/suricata/suricata.yaml  (test)
#                sudo systemctl restart suricata
