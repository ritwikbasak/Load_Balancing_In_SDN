import sys,numpy as np, matplotlib.pyplot as plt

def one_file(clients,algo):
    l=[]
    for i in range(clients):
        file = open('c' + str(i) + '-' + algo + '.txt')
        l.append(float(file.read()))
        file.close()

    return l

def start_exec():
    clients = int(sys.argv[1])
    algos = int(sys.argv[2])
    
    l=[]
    x_labels = []
    for i in range(algos):
        algo = sys.argv[i + 3]
        x_labels.append(algo)
        l.append(one_file(clients, algo))
    each_width = 0.8 / clients
    x_pos = 0 - each_width * (clients // 2)
    for i in range(clients):
        temp = [l[j][i] * 1000 for j in range(algos)]
        print(temp)
        plt.bar(np.arange(len(x_labels)) + x_pos, temp, each_width)
        x_pos += each_width
    
    plt.xticks(np.arange(len(x_labels)), x_labels, fontsize = 20)
    plt.yticks(fontsize = 20)
    plt.xlabel("Algorithms", fontsize = 20)
    plt.ylabel('avg. time per get request (in mS)' , fontsize = 20)
    plt.title("" , fontsize = 20)
    plt.legend()
    plt.show()

start_exec()