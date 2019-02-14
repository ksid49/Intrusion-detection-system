
# coding: utf-8

# In[1]:


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


# In[2]:


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
kdd_data = pandas.read_csv("kddcup.data_10_percent\\kddcup.data_10_percent_corrected", header=None, names = col_names)
kdd_data.describe()


# In[3]:


kdd_data = kdd_data.drop(['protocol_type','service','flag','num_outbound_cmds','is_host_login','label'], axis=1)


# In[4]:


kdd_data = kdd_data/kdd_data.max()
var = kdd_data.std()
var = var.sort_values(ascending = False)
print(var)


# In[5]:


corelation=kdd_data
c = corelation.corr().abs()
c = c.sum()
c = c.sort_values(ascending = True)
print(c)


# In[9]:


v = var.iloc[0:13].axes
c1 = c.iloc[0:13].axes
list1 = set(list(v[0]) + list(c1[0]))
print(list1, len(list1))

