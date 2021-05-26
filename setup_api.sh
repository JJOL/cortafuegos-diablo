python3 -m venv venv
source venv/bin/activate
pip install -r ids/requirements.txt

cd ids
export FLASK_APP=ids.py
flask run -h 0.0.0.0 -p 5000