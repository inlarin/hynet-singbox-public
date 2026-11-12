/ip firewall filter add chain=input action=accept in-interface=br-hynet comment="accept input from hynet container" place-before=[find where comment="defconf: drop all not coming from LAN"]
