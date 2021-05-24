from flask import Flask, request
import keras
import numpy as np
from pickle import load as pickle_load

app = Flask(__name__)

INPUT_FIELDS = [ "total_fpackets", "total_fvolume", "total_bpackets",
"total_bvolume", "min_fpktl", "mean_fpktl", "max_fptkl", "std_fpktl", "min_bpktl",
"mean_bpktl", "max_bpktl", "std_bpktl", "min_fiat", "mean_fiat", "max_fiat",
"std_fiat", "min_biat", "mean_biat", "max_biat", "std_biat", "duration", "min_active",
"mean_active", "max_active", "std_active", "min_idle", "mean_idle", "max_idle",
"std_idle", "sflow_fpackets", "sflow_fbytes", "sflow_bpackets", "sflow_bbytes",
"fpsh_cnt", "bpsh_cnt", "furg_cnt", "burg_cnt", "total_fhlen", "total_bhlen"]

# Load model before hand
model = keras.models.load_model("../model/model.h5")
with open("../model/scaler.pkl", "rb") as pickle_file:
    scaler = pickle_load(pickle_file)

@app.route("/", methods=["POST"])
def ids():
    errors = list()
    inpt = list()
    if request.is_json:
        data = request.get_json()
        # Check that all fields are in the request
        for field in INPUT_FIELDS:
            if not str(field) in data:
                errors.append({field: "Did not receive required field"})
            else:
                inpt.append(data[field])
        if not errors:
            array_raw = np.array([inpt])
            array = scaler.transform(array_raw)
            predictions = model.predict(array)
            return {"prediction": predictions.tolist()}, 200
    errors.append({"request": "Request is not in json format"})
    return errors, 400
