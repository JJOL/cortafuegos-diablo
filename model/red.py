from numpy import loadtxt
from keras.models import Sequential
from keras.layers import Dense, Dropout
from sklearn.preprocessing import MinMaxScaler
from keras.utils.vis_utils import plot_model
from matplotlib import pyplot as plt
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
import random
from pickle import dump

n = 132395
n_train = 92677
n_val = 11915

dataSet = loadtxt('AppDDoS.csv', delimiter=',');
random.shuffle(dataSet)
X = dataSet[:, 0:39]
singleY = dataSet[:,43]



i = 0
listY = []
for val in singleY:
	listY.append([0])
	if (val > 0) :
		listY[i][0] = 1
	i += 1

Y = np.array(listY)

trainX, testX = X[:n_train], X[n_train:]
trainY, testY = Y[:n_train], Y[n_train:]

valX = testX[:n_val]
valY = testY[:n_val]
testX = testX[n_val:]
testY = testY[n_val:]

scaler = MinMaxScaler()
scaler.fit(X)

normalizedTrain = scaler.transform(trainX)
normalizedTest = scaler.transform(testX)
normalizedVal = scaler.transform(valX)

model = Sequential()
model.add(Dense(32, input_dim=trainX.shape[1], activation='relu'))
model.add(Dropout(0.4))
model.add(Dense(8, activation='relu'))
#model.add(Dense(8, activation='relu'))
#model.add(Dense(10, activation='relu'))
model.add(Dense(1, activation='sigmoid'))

model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

history = model.fit(
	normalizedTrain,
	trainY,
	epochs=100,
	 batch_size=32,
	 validation_data=(normalizedVal, valY))

#print(model.summary())
#plot_model(model, to_file='model_plot.png', show_shapes=True, show_layer_names=True)
print(history.history.keys())
plt.plot(history.history['accuracy'])
plt.plot(history.history['val_accuracy'])
plt.title('model accuracy')
plt.ylabel('accuracy')
plt.xlabel('epoch')
plt.legend(['train', 'val'], loc='upper left')
plt.show()

plt.plot(history.history['loss'])
plt.plot(history.history['val_loss'])
plt.title('model loss')
plt.ylabel('loss')
plt.xlabel('epoch')
plt.legend(['train', 'val'], loc='upper left')
plt.show()

_, accuracy = model.evaluate(normalizedTest, testY)
predictions = model.predict(normalizedTest)

print(predictions[0])

y_pred = predictions > 0.5

#matrix = confusion_matrix(testY.argmax(axis=1), y_pred.argmax(axis=1))
matrix = confusion_matrix(testY, y_pred)

print(matrix)
print('Accuracy: %.2f' % (accuracy*100))

model.save('model.h5')
dump(scaler, open('scaler.pkl', 'wb'))
