# Correr solo si se va a entrenar nuevos modelos

python3 -m venv venv
source venv/bin/activate
pip install scikit-learn matplotlib tensorflow keras
cd model
python red.py
# model.h5 y scaler.pkl creados