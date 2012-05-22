gksudo rmmod -f iwlagn
gksudo modprobe iwlagn swcrypto=1
gksudo airmon-ng start wlan0
python -W ignore::DeprecationWarning pipe.py
