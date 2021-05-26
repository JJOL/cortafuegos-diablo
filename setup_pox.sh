# Setup POX Controller Files && Start POX

POX_DIR=/home/mininet/pox
CF_DIR=/home/mininet/cortafuegos-diablo

cp $CF_DIR/controller/ids_controller_p2.py $POX_DIR/ext/ids_controller.py

pip2 install -r controller/requirements.txt

cd $POX_DIR
python2 pox.py log.level --DEBUG forwarding.hub --reactive=False ids_controller --apiip=<192.168.1.68>