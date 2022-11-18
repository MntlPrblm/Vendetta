import json
import logging
import os
import random
import socket
import string
import sys
import time
import urllib
import traceback
import types
from collections import OrderedDict
from datetime import date
import nltk
import numpy as np
from nltk.stem import WordNetLemmatizer
from scapy.all import ARP, Ether, srp

import tensorflow as tf
from tensorflow.keras import Sequential
from tensorflow.keras.layers import Dense, Dropout

#checks to see if nltk data needs to be downloaded
if os.path.exists("nltkdata.txt") == False:
    f = open("nltkdata.txt", "x")
    print("Downloading nltk data...")
    nltk.download("punkt")
    nltk.download("wordnet")
else:
    print("nltk data found")

    #clears the screen
def clear():
    if os.name == "posix":
        _ = os.system('clear')
    else:
        _ = os.system('cls')

#start linecount for file change
previous_lc = 0

#opens data file
data_file = open('intents.json').read()
data = json.loads(data_file)

#creates list for arrays for data
words = []
classes = []
data_x = []
data_y = []

#appends arrays
for intent in data["intents"]:
    for pattern in intent["patterns"]:
        tokens = nltk.word_tokenize(pattern)
        words.extend(tokens)
        data_x.append(pattern)
        data_y.append(intent["tag"])
    if intent["tag"] not in classes:
        classes.append(intent["tag"])

#lemmatizes words for ease of function with neural network
lemmatizer = WordNetLemmatizer()
words = [lemmatizer.lemmatize(word.lower()) for word in words if word not in string.punctuation]
words = sorted(set(words))
classes = sorted(set(classes))

#converting words in to numbers using a bow model
training = []
out_empty = [0] * len(classes)

#creating bow model
for idx, doc in enumerate(data_x):
    bow = []
    text = lemmatizer.lemmatize(doc.lower())
    for word in words:
        bow.append(1) if word in text else bow.append(0)
    output_row = list(out_empty)
    output_row[classes.index(data_y[idx])] = 1
    training.append([bow, output_row])

#shuffles data and converts it to an array
random.shuffle(training)
training = np.array(training, dtype=object)
train_x = np.array(list(training[:,0]))
train_y = np.array(list(training[:,1]))

#building the model
model = Sequential()
model.add(Dense(128, input_shape=(len(train_x[0]),), activation="relu"))
model.add(Dropout(0.5))
model.add(Dense(64, activation="relu"))
model.add(Dropout(0.5))
model.add(Dense(len(train_y[0]), activation="softmax"))
adam = tf.keras.optimizers.Adam(learning_rate=0.01, decay=1e-6)
model.compile(loss='categorical_crossentropy', optimizer=adam, metrics=["accuracy"])
clear()
print("Training model...")
model.fit(x=train_x, y=train_y, epochs=150, verbose=1)

#preprocessing input
def clean_text(text):
    tokens = nltk.word_tokenize(text)
    tokens = [lemmatizer.lemmatize(word) for word in tokens]
    return tokens

def bag_of_words(text, vocab):
    tokens = clean_text(text)
    bow = [0] * len(vocab)
    for w in tokens:
        for idx, word in enumerate(vocab):
            if word == w:
                bow[idx] = 1
    return np.array(bow)

def pred_class(text, vocab, labels):
    bow = bag_of_words(text, vocab)
    result = model.predict(np.array([bow]), verbose=0)[0]
    thresh = 0.5
    y_pred = [[indx, res] for indx, res in enumerate(result) if res > thresh]
    y_pred.sort(key=lambda x: x[1], reverse=True)
    return_list = []
    for r in y_pred:
        return_list.append(labels[r[0]])
    return return_list

def get_response(intents_list, intents_json):
    if len(intents_list) == 0:
        result = "Sorry, I do not understand"
    else:
        tag = intents_list[0]
        list_of_intents = intents_json["intents"]
        for i in list_of_intents:
            if i["tag"] == tag:
                result = random.choice(i["responses"])
                break
    return result

#function to help count file
def blocks(files, size=65536):
    while True:
        b = files.read(size)
        if not b: break
        yield b

titlescreen = """
=======================
Vendetta 1.o
=======================
"""

def start():
    global previous_lc
    clear()
    #detects intents.json for changes
    with open("intents.json", "r",encoding="utf-8") as f:
        current_lc = sum(bl.count("\n") for bl in blocks(f)) + 1
    if current_lc != previous_lc:
        if previous_lc != 0:
            exec(open("restart.py").read())
        else:
            previous_lc = current_lc

    print(titlescreen)
    print("previous line count: "+str(previous_lc))
    print("json line count: "+str(current_lc))
    while True:
        user_in = input("Input: ")
        #hard coded responses and functions-----------------------------------
        #deletes log
        if "removelog" in user_in:
            user_in = user_in.split(" ")[1]
            if os.path.exists("./logs/"+user_in) == True:
                os.remove("./logs/"+user_in)
            else:
                print("file not found")

        #reads log files
        if "readlog" in user_in:
            user_in = user_in.split(" ")[1]
            if os.path.exists('./logs/'+user_in) == True:
                f = open('./logs/'+user_in)
                lines = f.read().splitlines()
                f.close
                for line in lines:
                    print(line)
            else:
                print(user_in+" not found")
        #shows all files in log folder
        if user_in == "show logs":
            print(os.listdir('./logs'))
        #if user wants to quit
        if user_in == "quit":
            break
            sys.exit()
        #if the user wants to train program
        if user_in == "train":
            exec(open("restart.py").read())
            sys.exit()
        if "network scan" in user_in:
            network_scan()
        #clears the screen on command
        if user_in == "clear":
            clear()
        #goes to intents.json for response----------------------------------------
        intents = pred_class(user_in, words, classes)
        result = get_response(intents, data)
        print("Vendetta: "+result)

#checks to see if there is an active connection
def check_connection():
    try:
        socket.create_connection(("1.1.1.1", 53))
        print("found connection")
    except OSError:
        print("network connection not found")
        time.sleep(1)
        start()

#shows who is on your network
def network_scan():
    check_connection()
    print("Starting network scan")
    target_ip = "192.168.1.1/24"
    # IP Address for the destination
    # create ARP packet
    arp = ARP(pdst=target_ip)
    # create the Ether broadcast packet
    # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # stack them
    packet = ether/arp
    try:
        result = srp(packet, timeout=3)[0]
    except RuntimeError:
        clear()
        print("You dont have winpcap installed, get it here:")
        print("https://www.winpcap.org/install/")
        print("once installed close this terminal and restart")
        input("Press enter to continue")
        start()
    # a list of clients, we will fill this in the upcoming loop
    clients = []
    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    # print clients
    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))
    #saves network scan to logs directory
    save_network_scan = input("Save network scan? y or n: ")
    if save_network_scan == "y":
        try:
            os.mkdir("logs")
        except OSError:
            print("log directory found")
        f1 = open('./logs/'+str(date.today())+'_ns.txt', 'a')
        for client in clients:
            f1.write("{:16}    {}".format(client['ip'], client['mac']))
            f1.write('\n')
        f1.close()

    



if __name__=="__main__":
    start()


