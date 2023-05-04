import matplotlib.pyplot as plt
import numpy as np
from sklearn import datasets, linear_model
from sklearn.metrics import mean_squared_error, r2_score
import json

with open("Jsons/devices_IA_clases.json", "r") as f:
    trainDevices = json.load(f)

with open("Jsons/devices_IA_predecir_v2.json", "r") as f:
    testDevices = json.load(f)

xTrain = []
yTrain = []
xTest = []
yTest = []
yPredict = []
for i in trainDevices:
    if i['servicios'] == 0:
        xTrain.append([0])
    else:
        xTrain.append([i['servicios_inseguros']/i['servicios']])
    yTrain.append([i['peligroso']])

for i in testDevices:
    if i['servicios'] == 0:
        xTest.append([0])
    else:
        xTest.append([i['servicios_inseguros'] / i['servicios']])
    yTest.append([i['peligroso']])


regr = linear_model.LinearRegression()
regr.fit(xTrain,yTrain)

yPredict = regr.predict(xTest)
print("Mean squared error: %.2f" % mean_squared_error(yTest, yPredict))
# Plot outputs
plt.scatter(xTest, yTest, color="black")
plt.plot(xTest, yPredict, color="blue", linewidth=3)
plt.xticks(())
plt.yticks(())
plt.show()
