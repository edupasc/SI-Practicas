import matplotlib.pyplot as plt
import numpy as np
from sklearn import datasets, tree
from sklearn.metrics import mean_squared_error, r2_score
import json
import graphviz #https://graphviz.org/download/

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


clf = tree.DecisionTreeClassifier()
clf.fit(xTrain,yTrain)


dot_data = tree.export_graphviz(clf, out_file=None,
                      feature_names=['Porcentaje'],
                      class_names=['peligroso','noPeligroso'],
                     filled=True, rounded=True,
                    special_characters=True)
graph = graphviz.Source(dot_data)
graph.render('test.gv', view=True).replace('\\', '/')

yPredict = clf.predict(xTest)
print("Mean squared error: %.2f" % mean_squared_error(yTest, yPredict))