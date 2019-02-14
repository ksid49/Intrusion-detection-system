
# coding: utf-8

# In[10]:


import keras
import pandas
from keras.models import Sequential
from keras.layers import Activation, Dropout, Flatten, Dense, BatchNormalization
from keras.optimizers import SGD
import numpy as np
from time import time
from collections import Counter
import datetime
from keras.callbacks import CSVLogger, EarlyStopping, ModelCheckpoint


# In[233]:


col_names = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label"]
kdd_data = pandas.read_csv("data\\dataset2", header=None, names = col_names)
kdd_data.describe()


# In[234]:


train_labels = np.array(kdd_data['label'])
kdd_data = kdd_data.drop(['protocol_type','service','flag','num_outbound_cmds','is_host_login','label','num_compromised',
                          'su_attempted','num_root','rerror_rate','diff_srv_rate','srv_diff_host_rate','dst_host_diff_srv_rate',
                          'dst_host_srv_diff_host_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate'], axis=1)



# In[235]:


#print(kdd_data.count)
kdd_data=kdd_data/kdd_data.max()
train_data = kdd_data.values
train_data = train_data[:,:]

#print(kdd_data.count)


x = list(set(train_labels))


# In[236]:


#converting labels into 5 types
train_label2 = []
for label in train_labels:
    if label in ['nmap.', 'portsweep.', 'ipsweep.', 'satan.','mscan.','saint.']:
        label = 'probing'
    elif label in ['land.','pod.','teardrop.','back.','neptune.','smurf.','apache2.','mailbomb.','processtable.','udpstorm.']:
        label = 'dos'
    elif label in ['spy.', 'phf.', 'multihop.', 'ftp_write.', 'imap.', 'warezmaster.', 'warezclient.', 'guess_passwd.','sendmail.','named.','snmpgetattack.','snmpguess.','xlock.','xsnoop.','worm.']:
        label = 'r2l'
    elif label in ['buffer_overflow.', 'rootkit.','loadmodule.','perl.','httptunnel.','ps.','sqlattack.','xterm.']:
        label = 'u2r'
    train_label2.append(label)


# In[237]:


#converting labels into int format
y = list(set(train_label2))
dictY = {}
for i, label in enumerate(y):
    dictY.update({label:i})
print(dictY)
train_label3 = []
for label in train_label2:
    train_label3.append(dictY[label])
print(len(train_label3))
#converting int labels into one hot encoding
one_hot_labels = keras.utils.to_categorical(train_label3, num_classes=5)
print(one_hot_labels)


# In[238]:


model = Sequential()
model.add(Dense(12, input_shape= (train_data.shape[1],), activation='relu'))
model.add(BatchNormalization())
#model.add(Dropout(0.5, name='dropout_1'))
model.add(Dense(5, activation='softmax'))

sgd = SGD(lr=1e-4, decay=1e-5, momentum=0.9, nesterov=True,clipnorm=0.1)
model.compile(optimizer=sgd,
              loss='categorical_crossentropy', metrics=['accuracy'])

#model.load_weights('model.h5')
csv_logger = CSVLogger("training1.csv")
checkpoint = ModelCheckpoint("model.h5", monitor='val_acc', verbose=1, save_best_only=True, save_weights_only=False, mode='auto', period=1)
model.fit(train_data, one_hot_labels, batch_size = 100, epochs = 20, verbose = 1, validation_split = 0.2, callbacks = [csv_logger, checkpoint])


# In[239]:



model.load_weights('model.h5')
x = model.predict_classes(train_data)
print(x)
j = 0
for i, d in enumerate(x):
    if d == train_label3[i]:
        j = j+1
print(j/len(x))


# In[240]:


col_names = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label"]
kdd_data2 = pandas.read_csv("corrected\\corrected", header=None, names = col_names)
kdd_data2.describe()


# In[241]:


test_labels = np.array(kdd_data2['label'])
kdd_data2 = kdd_data2.drop(['protocol_type','service','flag','num_outbound_cmds','is_host_login','label','num_compromised',
                            'su_attempted','num_root','rerror_rate','diff_srv_rate','srv_diff_host_rate',
                            'dst_host_diff_srv_rate','dst_host_srv_diff_host_rate','dst_host_rerror_rate',
                            'dst_host_srv_rerror_rate'], axis=1)


# In[242]:


kdd_data2=kdd_data2/kdd_data2.max()
test_data = kdd_data2.values
test_data = test_data[:,:]


#converting labels into 5 types
test_label2 = []
for label in test_labels:
    if label in ['nmap.', 'portsweep.', 'ipsweep.', 'satan.','mscan.','saint.']:
        label = 'probing'
    elif label in ['land.','pod.','teardrop.','back.','neptune.','smurf.','apache2.','mailbomb.','processtable.','udpstorm.']:
        label = 'dos'
    elif label in ['spy.', 'phf.', 'multihop.', 'ftp_write.', 'imap.', 'warezmaster.', 'warezclient.', 'guess_passwd.','sendmail.','named.','snmpgetattack.','snmpguess.','xlock.','xsnoop.','worm.']:
        label = 'r2l'
    elif label in ['buffer_overflow.', 'rootkit.','loadmodule.','perl.','httptunnel.','ps.','sqlattack.','xterm.']:
        label = 'u2r'
    test_label2.append(label)

y2 = list(set(test_label2))
test_label3 = []
for label in test_label2:
    if label in dictY.keys():
        test_label3.append(dictY[label])
print(set(test_label3))

model.load_weights('model.h5')
x = model.predict_classes(test_data)
print(x)
j = 0
for i, d in enumerate(test_label3):
    if d == x[i] :
        j = j+1
print(j/len(test_label3))


# In[243]:


j=0
typeA=0
typeB=0
typeC=0
typeD=0
typeE=0
for i, d in enumerate(test_label3):
    if d == x[i] :
        if d==0:
            typeA = typeA+1
        elif d==1:
            typeB = typeB+1
        elif d==2:
            typeC = typeC+1
        elif d==3:
            typeD = typeD+1
        elif d==4:
            typeE = typeE+1
        j = j+1
print(j/len(test_label3))
print(typeA,typeB,typeC,typeD,typeE)


# In[244]:


i=(1)
q=Counter(x)
print(q)


# In[245]:


from sklearn.metrics import confusion_matrix


con=confusion_matrix(x,test_label3)
print(con)


# In[246]:


par=np.zeros((4,5))

for i in range (0,5):
    par[0,i]=con[i,i]
    
for i in range (0,5):
    for j in range (0,5):
        if i!=j:
            par[1,i]=par[1,i]+con[i,j]

for i in range (0,5):
    for j in range (0,5):
        if i!=j:
            par[2,i]=par[2,i]+con[j,i]        

for i in range (0,5):
    for j in range (0,5):
        for k in range (0,5):
            if j!=i and k!=i:
                par[3,i]=par[3,i]+con[i,j]

                
#2D matrix par
#tp-0
#fn-1
#fp-2
#tn-3
#2D matrix ratio
#tpr-4
#fpr-5
#precision-6
#accuracy-7
ratio=np.zeros((4,5))
for i in range (0,5):
    ratio[0,i]=(par[0,i]/(par[0,i]+par[1,i]))*100
    
for i in range (0,5):
    ratio[1,i]=(par[2,i]/(par[2,i]+par[3,i]))*100
for i in range (0,5):
    ratio[2,i]=par[0,i]/(par[0,i]+par[2,i])
for i in range (0,5):
    ratio[3,i]=((par[0,i]+par[3,i])/(par[0,i]+par[1,i]+par[2,i]+par[3,i]))*100


np.set_printoptions(formatter={'float_kind':'{:f}'.format})       
print('Parameters')
print(par.astype(int))
print('Parameter ratio')
print(ratio)


# VALUES
# normal=2
# u2r=1
# r2l=0
# probe=3
# dos=4
