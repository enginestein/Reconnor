# MAC Address Lookup

Looks up the vendor/OUI for a MAC address using the macvendors.com API and a local OUI database.

```
python3 main.py mac-address 00:11:22:33:44:55
python3 main.py mac-address 00:11:22:AA:BB:CC
```

**Output:** Vendor name, OUI prefix, MAC type (unicast/multicast, globally unique/locally administered).

**How it works:** Queries macvendors.com API first, falls back to a local OUI database.
