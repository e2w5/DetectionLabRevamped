# make a local props override for the TA
sudo mkdir -p /opt/splunk/etc/apps/Splunk_TA_paloalto/local
cat <<'EOF' | sudo tee /opt/splunk/etc/apps/Splunk_TA_paloalto/local/props.conf >/dev/null
[pan:traffic]
LOOKUP-minemeldfeeds_dest_lookup =
LOOKUP-minemeldfeeds_src_lookup =

[pan:threat]
LOOKUP-minemeldfeeds_dest_lookup =
LOOKUP-minemeldfeeds_src_lookup =
EOF

# restart to apply
sudo /opt/splunk/bin/splunk restart
exit

-time scale to all times

2.1 replace ip with domain name

