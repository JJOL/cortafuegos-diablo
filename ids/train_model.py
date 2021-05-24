from numpy import loadtxt
from keras.models import Sequential
from keras.layers import Dense
from sklearn.preprocessing import MinMaxScaler
import numpy as np

n = 132395
n_train = 105916

dataSet = loadtxt('AppDDoS.csv', delimiter=',');
X = dataSet[:,0:43]
singleY = dataSet[:,43]

i = int(0)
listY = []
for val in singleY:
	listY.append([0,0,0,0,0,0,0,0,0])
	listY[i][int(val)] = 1
	i += 1

Y = np.array(listY)

trainX, testX = X[:n_train], X[n_train:]
trainY, testY = Y[:n_train], Y[n_train:]

scaler = MinMaxScaler()
scaler.fit(X)
normalizedTrain = scaler.transform(trainX)
normalizedTest = scaler.transform(testX)

model = Sequential()
model.add(Dense(43, input_dim=43, activation='relu'))
model.add(Dense(21, activation='relu'))
model.add(Dense(9, activation='sigmoid'))

model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

model.fit(normalizedTrain,trainY,epochs=1500, batch_size=100)

# evaluate the keras model
_, accuracy = model.evaluate(testX, testY)
print('Accuracy: %.2f' % (accuracy*100))

# Save model
model.save("model.h5")
