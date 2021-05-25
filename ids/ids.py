"""
Cortafuegos-Diablo: IDS Classification API
Author: Doritos Electronicos
Descripcion: Una pequeña API REST en flask que recibe peticiones en formato json con las features de flowbag y responde
una probabilidad de que el flow represente tráfico de ataque SR-DDoS
"""

from flask import Flask, request
import keras
import numpy as np
from pickle import load as pickle_load

app = Flask(__name__)

INPUT_FIELDS = [ "total_fpackets", "total_fvolume", "total_bpackets",
"total_bvolume", "min_fpktl", "mean_fpktl", "max_fpktl", "std_fpktl", "min_bpktl",
"mean_bpktl", "max_bpktl", "std_bpktl", "min_fiat", "mean_fiat", "max_fiat",
"std_fiat", "min_biat", "mean_biat", "max_biat", "std_biat", "duration", "min_active",
"mean_active", "max_active", "std_active", "min_idle", "mean_idle", "max_idle",
"std_idle", "sflow_fpackets", "sflow_fbytes", "sflow_bpackets", "sflow_bbytes",
"fpsh_cnt", "bpsh_cnt", "furg_cnt", "burg_cnt", "total_fhlen", "total_bhlen"]

# Load model and input scaler before hand
model = keras.models.load_model("../model/model.h5")
with open("../model/scaler.pkl", "rb") as pickle_file:
    scaler = pickle_load(pickle_file)

@app.route("/", methods=["POST"])
def ids():
    print('Peticion recibida...')
    errors = list()
    inpt = list()
    if request.is_json:
        data = request.get_json()

        print('Input Data:')
        print(str(data))
        # Check that all fields are in the request
        
        for field in INPUT_FIELDS:
            if field not in data:
                errors.append({field: "Did not receive required field"})
            else:
                inpt.append(data[field])

        if not errors:
            array_raw = np.array([inpt])
            array = scaler.transform(array_raw)
            predictions = model.predict(array)
            print('Nuestra prediccion es p(x): ' + str(predictions[0][0]))
            return {"prediction": predictions.tolist()}, 200
        else:
            print('No se pudo hacer prediccion por siguientes errores:')
            print(errors)
            return {'errors': errors}, 400
            
    errors.append({"request": "Request is not in json format"})

    print('No se pudo hacer prediccion por siguientes errores:')
    print(errors)
    return {'errors': errors}, 400
