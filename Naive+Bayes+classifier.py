
# coding: utf-8

# In[16]:


import pandas
from time import time
from sklearn.metrics import accuracy_score
from collections import Counter
from sklearn.metrics import confusion_matrix
import numpy as np
from sklearn.cross_validation import train_test_split
from sklearn.naive_bayes import GaussianNB
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
kdd_data_10percent = pandas.read_csv("data\\dataset2", header=None, names = col_names)
kdd_data_10percent.describe()


# In[17]:


kdd_data_10percent['label'].value_counts()


# In[18]:



num_features = [
    "duration","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate"
]
features = kdd_data_10percent[num_features].astype(float)
features.describe()


# In[19]:



train_labels = kdd_data_10percent['label'].copy()
labels = []


for label in train_labels:
    if label in ['nmap.', 'portsweep.', 'ipsweep.', 'satan.','mscan.','saint.']:
        label = 'probing'
    elif label in ['land.','pod.','teardrop.','back.','neptune.','smurf.','apache2.','mailbomb.','processtable.','udpstorm.']:
        label = 'dos'
    elif label in ['spy.', 'phf.', 'multihop.', 'ftp_write.', 'imap.', 'warezmaster.', 'warezclient.', 'guess_passwd.','sendmail.','named.','snmpgetattack.','snmpguess.','xlock.','xsnoop.','worm.']:
        label = 'r2l'
    elif label in ['buffer_overflow.', 'rootkit.','loadmodule.','perl.','httptunnel.','ps.','sqlattack.','xterm.']:
        label = 'u2r'
    labels.append(label)
labels = pandas.Series( (v[0] for v in labels) )
print(type(labels))
labels.value_counts()


# In[20]:


features.shape


# In[21]:



t0 = time()

gnb = GaussianNB().fit(features,labels)
tt = time()-t0
print ( "Classifier trained in {} seconds".format(round(tt,3)))


# In[22]:


kdd_data_corrected = pandas.read_csv("corrected\\corrected", header=None, names = col_names)
kdd_data_corrected['label'].value_counts()


# In[23]:


train_labels = kdd_data_corrected['label'].copy()
labels_test = []


for label in train_labels:
    if label in ['nmap.', 'portsweep.', 'ipsweep.', 'satan.','mscan.','saint.']:
        label = 'probing'
    elif label in ['land.','pod.','teardrop.','back.','neptune.','smurf.','apache2.','mailbomb.','processtable.','udpstorm.']:
        label = 'dos'
    elif label in ['spy.', 'phf.', 'multihop.', 'ftp_write.', 'imap.', 'warezmaster.', 'warezclient.', 'guess_passwd.','sendmail.','named.','snmpgetattack.','snmpguess.','xlock.','xsnoop.','worm.']:
        label = 'r2l'
    elif label in ['buffer_overflow.', 'rootkit.','loadmodule.','perl.','httptunnel.','ps.','sqlattack.','xterm.']:
        label = 'u2r'
    labels_test.append(label)
labels_test = pandas.Series( (v[0] for v in labels) )


# In[24]:


#kdd_data_corrected['label'][kdd_data_corrected['label']!='normal.'] = 'attack.'
kdd_data_corrected['label']=labels_test[:]
kdd_data_corrected['label'].value_counts()


# In[25]:



kdd_data_corrected[num_features] = kdd_data_corrected[num_features].astype(float)
#kdd_data_corrected[num_features].apply(lambda x: MinMaxScaler().fit_transform(x))


# In[26]:


features_train, features_test, labels_train, labels_test = train_test_split(
    kdd_data_corrected[num_features], 
    kdd_data_corrected['label'],  
    random_state=0)


# In[27]:



t0 = time()
pred = gnb.predict(features_test)

tt = time() - t0
print ("Predicted in {} seconds".format(round(tt,3)))


# In[28]:



#print(type(labels))
print(labels_test.value_counts())
i=(1)
q=Counter(pred)
print(q)

acc = accuracy_score(pred, labels_test)
print ("R squared is {}.".format(round(acc,4)))


# In[ ]:



con = confusion_matrix(pred,labels_test)
print(pred[0])
print(con)
#d=0
#n=1
#p=2
#r=3
#u=4


# In[ ]:



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

