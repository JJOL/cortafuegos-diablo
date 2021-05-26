# Start Running MiniNet with topology

sudo mn --topo single,3 --mac  --controller remote

# In MININET
#pingall
#xterm h1
#xterm h2
# In Host H1 X11
#python -m SimpleHTTPServer

# In Host H2 X11
#wget -O 10.0.0.1
#slowhttptest -u http://10.0.0.1