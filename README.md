# nmapj

A wrapper around [nmap](https://nmap.org/) that prints JSONL output.

# Setup

Install the Python package.

a) With [pipx](https://github.com/pypa/pipx).

~~~ bash
pipx install git+https://github.com/dadevel/nmapjson.git@main
~~~

b) With [pip](https://github.com/pypa/pip).

~~~ bash
pip install --user git+https://github.com/dadevel/nmapjson.git@main
~~~

Optional: Give unprivileged `nmap` processes access to raw sockets.

~~~ bash
sudo setcap CAP_NET_RAW=ep "$(which nmap)"
~~~

# Usage

Discover web servers and scan them with [nuclei](https://github.com/projectdiscovery/nuclei).

~~~ bash
nmapj -A 192.168.1.0/24 | \
  tee ./nmap.json | \
  jq -r 'select(.application=="http")|"\(.address):\(.port)"' | \
  nuclei -silent -automatic-scan
~~~

# Tips

Balance scanning of large networks over multiple `nmap` processes.
The example runs 16 processes in parallel with 128 IPs per process.

~~~ bash
echo 192.168.0.0/16 | \
  mapcidr -silent | \
  parallel --progress --pipe --ungroup --jobs 16 -N 128 -- nmapj --privileged -iL - -n -Pn -T4 --top-ports 100 -sS -sV --version-intensity 0 | \
  tee ./nmap.json
~~~
