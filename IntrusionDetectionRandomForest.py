import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import time

#reading features list from ‘kddcup.names’ file
with open(r"C:\Users\Zoya\Downloads/kddcup.names") as f:
    print(f.read())

# Appending columns to the dataset and adding a
#new column name ‘target’ to the dataset
cols="""duration,
protocol_type,
service,
flag,
src_bytes,
dst_bytes,
land,
wrong_fragment,
urgent,
hot,
num_failed_logins,
logged_in,
num_compromised,
root_shell,
su_attempted,
num_root,
num_file_creations,
num_shells,
num_access_files,
num_outbound_cmds,
is_host_login,
is_guest_login,
count,
srv_count,
serror_rate,
srv_serror_rate,
rerror_rate,
srv_rerror_rate,
same_srv_rate,
diff_srv_rate,
srv_diff_host_rate,
dst_host_count,
dst_host_srv_count,
dst_host_same_srv_rate,
dst_host_diff_srv_rate,
dst_host_same_src_port_rate,
dst_host_srv_diff_host_rate,
dst_host_serror_rate,
dst_host_srv_serror_rate,
dst_host_rerror_rate,
dst_host_srv_rerror_rate"""

columns=[]
for c in cols.split(','):
    if(c.strip()):
       columns.append(c.strip())

columns.append('target')
#print(columns)
print(len(columns))

#Reading the C:\Users\Zoya\Downloads/training_attack_types") as f:
    print(f.read())

#Creating a dictionary of attack_types
attacks_types = {
    'normal': 'normal',
'back': 'dos',
'buffer_overflow': 'u2r',
'ftp_write': 'r2l',
'guess_passwd': 'r2l',
'imap': 'r2l',
'ipsweep': 'probe',
'land': 'dos',
'loadmodule': 'u2r',
'multihop': 'r2l',
'neptune': 'dos',
'nmap': 'probe',
'perl': 'u2r',
'phf': 'r2l',
'pod': 'dos',
'portsweep': 'probe',
'rootkit': 'u2r',
'satan': 'probe',
'smurf': 'dos',
'spy': 'r2l',
'teardrop': 'dos',
'warezclient': 'r2l',
'warezmaster': 'r2l',
}

#Reading the dataset(‘kddcup.data_10_percent.gz’) and
#adding Attack Type feature in the training dataset where attack type
#feature has 5 distinct values i.e. dos, normal, probe, r2l, u2r.
df = pd.read_csv(r"C:\Users\Zoya\Downloads/kddcup.data_10_percent.gz", names=columns)

#Adding Attack Type column
df['Attack Type'] = df.target.apply(lambda r:attacks_types[r[:-1]])

df.head()

#Shape of dataframe
df.shape

df['target'].value_counts()

#Data Correlation – Find the highly correlated variables
#using heatmap and ignore them for analysis.
df = df.dropna('columns')# drop columns with NaN

df = df[[col for col in df if df[col].nunique() > 1]]# keep columns where there are more than 1 unique values

corr = df.corr()

plt.figure(figsize=(15,12))

sns.heatmap(corr, square=True, annot=True, fmt='.2f', linecolor='white')

plt.show()

#This variable is highly correlated with num_compromised and should be ignored for analysis.
#(Correlation = 0.9938277978738366)
df.drop('num_root',axis = 1,inplace = True)

#This variable is highly correlated with serror_rate and should be ignored for analysis.
#(Correlation = 0.9983615072725952)
df.drop('srv_serror_rate',axis = 1,inplace = True)

#This variable is highly correlated with rerror_rate and should be ignored for analysis.
#(Correlation = 0.9947309539817937)
df.drop('srv_rerror_rate',axis = 1, inplace=True)

#This variable is highly correlated with srv_serror_rate and should be ignored for analysis.
#(Correlation = 0.9993041091850098)
df.drop('dst_host_srv_serror_rate',axis = 1, inplace=True)

#This variable is highly correlated with rerror_rate and should be ignored for analysis.
#(Correlation = 0.9869947924956001)
df.drop('dst_host_serror_rate',axis = 1, inplace=True)

#This variable is highly correlated with srv_rerror_rate and should be ignored for analysis.
#(Correlation = 0.9821663427308375)
df.drop('dst_host_rerror_rate',axis = 1, inplace=True)

#This variable is highly correlated with rerror_rate and should be ignored for analysis.
#(Correlation = 0.9851995540751249)
df.drop('dst_host_srv_rerror_rate',axis = 1, inplace=True)

#This variable is highly correlated with dst_host_srv_count and should be ignored for analysis.
#(Correlation = 0.9736854572953938)
df.drop('dst_host_same_srv_rate',axis = 1, inplace=True)

df.head()

df.shape

#count numer of protocol types by
df['protocol_type'].value_counts()

#protocol_type feature mapping
pmap = {'icmp':0,'tcp':1,'udp':2}
df['protocol_type'] = df['protocol_type'].map(pmap)

df['flag'].value_counts()

#flag feature mapping
fmap = {'SF':0,'S0':1,'REJ':2,'RSTR':3,'RSTO':4,'SH':5 ,'S1':6 ,'S2':7,'RSTOS0':8,'S3':9 ,'OTH':10}
df['flag'] = df['flag'].map(fmap)

df['Attack Type'].value_counts()

#Remove irrelevant features such as ‘service’ before modelling
#Remove target as its the same as Attack Type
df.drop('service',axis = 1,inplace= True)
df = df.drop(['target',], axis=1)
print(df.shape)

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score

X=df.drop(['Attack Type',], axis=1)
Y=df[['Attack Type']]
sc = StandardScaler()
X = sc.fit_transform(X)

# Split test and train data
X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.33, random_state=42)
print(X_train.shape, X_test.shape)
print(Y_train.shape, Y_test.shape)

#Random Forest

from sklearn.ensemble import RandomForestClassifier

model = RandomForestClassifier(n_estimators=30)

model.fit(X_train, Y_train.values.ravel())

Y_test_pred = model.predict(X_test)

print("Train score is:", model.score(X_train, Y_train))
print("Test score is:",model.score(X_test,Y_test))

from sklearn.metrics import accuracy_score
ac= accuracy_score(Y_test,Y_test_pred)
print(ac)

from yellowbrick.classifier import ConfusionMatrix

cm = ConfusionMatrix(model, classes=["dos","normal","probe","r2l","u2r"])

# Fit fits the passed model. This is unnecessary if you pass the visualizer a pre-fitted model
cm.fit(X_train, Y_train)

# To create the ConfusionMatrix, we need some test data. Score runs predict() on the data
# and then creates the confusion_matrix from scikit-learn.
cm.score(X_test, Y_test)

# How did we do?
cm.show()

from sklearn.metrics import classification_report

print(classification_report(Y_test, Y_test_pred))

from sklearn.model_selection import cross_val_score

scores = cross_val_score(model, X_train, Y_train, cv = 10, scoring = 'accuracy')
print("cross-validation scores: {}".format(scores))
print("Average cross-validation score:{:.2f}".format(scores.mean()))

#Learning curve
from yellowbrick.model_selection import LearningCurve
sizes = np.linspace(0.3, 1.0, 10)
visualizer = LearningCurve(
    model, cv=5, scoring='f1_weighted', train_sizes=sizes, n_jobs=4
)

visualizer.fit(X, Y)        # Fit the data to the visualizer
visualizer.show()


from yellowbrick.model_selection import FeatureImportances
viz = FeatureImportances(model)
viz.fit(X, Y)
viz.show()