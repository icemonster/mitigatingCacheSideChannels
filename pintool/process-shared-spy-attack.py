import ast
import matplotlib.pyplot as plt

with open('results.txt') as f:
    data = ast.literal_eval(f.read())

def metric(result):
    d, leaked = result
    correct = 0
    for i in range(len(d)):
        correct += (d[i] == leaked[i])
    return correct

results = []
print(data[1])
for noise in range(1,100,2):
    results.append(metric(data[noise]))
    print(noise, '-->', results[-1])

plt.plot(list(range(1, 100, 2)), results)
plt.axis([0, 100, 400, 1024])
plt.axline((0,512), (100, 512)) # Expected correct number of bits for random oracle
plt.xlabel('Noise')
plt.ylabel('Correct bits')
plt.show()