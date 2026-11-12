:foreach c in={"10.0.0.0/8";"172.16.0.0/12";"192.168.0.0/16"} do={ /ip firewall address-list add list=hynet-direct address=$c comment="hynet:direct-private" }
/ip route add dst-address=0.0.0.0/0 gateway=172.20.0.2 routing-table=via-hynet distance=1 check-gateway=ping comment="hynet container"
/ip route add dst-address=0.0.0.0/0 blackhole routing-table=via-hynet distance=10 comment="hynet killswitch"
/ip firewall mangle add chain=prerouting src-address=<TENDA-NAT-IP> dst-address-list=hynet-direct action=accept passthrough=yes comment="hynet: Tenda private bypass"
/ip firewall mangle add chain=prerouting src-address=<TENDA-NAT-IP> dst-address-type=local action=accept passthrough=yes comment="hynet: Tenda router bypass"
/ip firewall mangle add chain=prerouting src-address=<TENDA-NAT-IP> connection-state=new dst-address-list=hynet action=mark-connection new-connection-mark=hynet-cm passthrough=yes comment="hynet: Tenda selected services"
/ip firewall mangle add chain=prerouting src-address=<TENDA-NAT-IP> connection-mark=hynet-cm action=mark-routing new-routing-mark=via-hynet passthrough=no comment="hynet: Tenda only"
/ip firewall mangle add chain=forward action=change-mss new-mss=clamp-to-pmtu protocol=tcp tcp-flags=syn out-interface=br-hynet comment="hynet MSS clamp"
