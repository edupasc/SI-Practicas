import matplotlib.pyplot as plt
import numpy as np
from sklearn import datasets, linear_model
from sklearn.ensemble import RandomForestClassifier
from subprocess import call
import json

from sklearn.metrics import mean_squared_error
from sklearn.tree import export_graphviz

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

clf = RandomForestClassifier(max_depth=2, random_state=0,n_estimators=10)
clf.fit(xTrain,yTrain)

for i in range(len(clf.estimators_)):
    print(i)
    estimator = clf.estimators_[i]
    export_graphviz(estimator,
                    out_file='tree.dot',
                    feature_names=['Porcentaje'],
                    class_names=['peligroso','noPeligroso'],
                    rounded=True, proportion=False,
                    precision=2, filled=True)
    call(['dot', '-Tpng', 'tree.dot', '-o', 'tree'+str(i)+'.png', '-Gdpi=600'])


yPredict = clf.predict(xTest)
print("Mean squared error: %.2f" % mean_squared_error(yTest, yPredict))