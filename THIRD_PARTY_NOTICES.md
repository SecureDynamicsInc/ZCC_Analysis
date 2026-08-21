# Third-party notices

ZCC Log Explorer is distributed under the Apache License 2.0. Its Python
environment installs the following direct open-source dependencies at runtime;
they are not copied into this repository.

| Component | Purpose | License | Project |
| --- | --- | --- | --- |
| Streamlit | Local web interface | Apache-2.0 | https://github.com/streamlit/streamlit |
| MaxMind DB Reader for Python (`maxminddb`) | Optional local GeoIP database reader | Apache-2.0 | https://github.com/maxmind/MaxMind-DB-Reader-python |
| pytest | Development and verification only | MIT | https://github.com/pytest-dev/pytest |

The analyzer can use a GeoLite2 database that the user downloads separately.
No GeoLite2 database is distributed with this repository. GeoLite2 use and
redistribution are governed by MaxMind's terms and attribution requirements:
https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/

Wireshark, Codex, Claude Code, GitHub, and Zscaler products are optional or
external tools and services. They are not bundled with this project. Their
names and marks belong to their respective owners.

This file is informational and does not modify the Apache License 2.0.
