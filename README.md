## Installation

# Unifi Controller
This module provides device that can trigger a custom script upon controller events.

The respective discovery module is currently only a placeholder, and just lists a controller at 192.168.1.1 - if you are using a different IP, just add a controller manually, provide password & username, and configure the socket accordingly (using SSL, disable verification, port 443).

# Unifi Protect
This module provides individual camera devices that can inform you about motion & smart detection events, as well as rings (for the Doorbell).

There is currently no discovery module available. Just add a camera manually; you can get the needed UnifiID from the protect web application. On the camera profile page it is the last part of the URL (e.g. https://unifi.local/protect/devices/<UnifiID>). Then configure the protect device with password & username, and the socket accordingly for your controller (using SSL, disable verification, port 443).

## Attribution

WebSocket protocol implementation based on [IPSNetwork](https://github.com/Nall-chan/IPSNetwork) by [Nall-chan](https://github.com/Nall-chan)

## Licence
[CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/)  