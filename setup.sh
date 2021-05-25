# Setup POX Controller Files

POX_DIR=/home/mininet/pox
CF_DIR=/home/mininet/cortafuegos-diablo

cp $CF_DIR/controller/ids_controller_p2.py $POX_DIR/ext/ids_controller.py

pip2 install -r controller/requirements.txt

cd $POX_DIR
./pox.py log.level --DEBUG forwarding.l3_learning ids_controller --apiip=192.168.1.68