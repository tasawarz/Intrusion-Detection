# Import Python Libraries
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# reading features list from ‘kddcup.names’ file
with open(r"C:\Users\Zoya\Downloads/kddcup.names") as f:
    print(f.read())

# Appending columns to the dataset and adding a
# new column name ‘target’ to the dataset
cols = """duration, protocol_type, service, flag, src_bytes, dst_bytes, land, wrong_fragment, urgent, hot,
num_failed_logins, logged_in,num_compromised,root_shell,su_attempted,num_root,num_file_creations,
num_shells,num_access_files,num_outbound_cmds,is_host_login,is_guest_login,count,srv_count,serror_rate,srv_serror_rate,
rerror_rate,srv_rerror_rate,same_srv_rate,diff_srv_rate,srv_diff_host_rate,dst_host_count,dst_host_srv_count,
dst_host_same_srv_rate,dst_host_diff_srv_rate,dst_host_same_src_port_rate,dst_host_srv_diff_host_rate,dst_host_serror_rate,
dst_host_srv_serror_rate,dst_host_rerror_rate,dst_host_srv_rerror_rate"""

columns = []
for c in cols.split(','):
    if (c.strip()):
        columns.append(c.strip())

columns.append('target')
# print(columns)
print(len(columns))

# Reading the ‘attack_types’ file.
with open(r"C:\Users\Zoya\Downloads/training_attack_types") as f:
    print(f.read())

# Creating a dictionary of attack_types
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

# Reading the dataset(‘kddcup.data_10_percent.gz’) and
df = pd.read_csv(r"C:\Users\Zoya\Downloads/kddcup.data_10_percent.gz", names=columns)

# adding Attack Type feature in the training dataset where attack type
# feature has 5 distinct values i.e. dos, normal, probe, r2l, u2r.
df['Attack Type'] = df.target.apply(lambda r: attacks_types[r[:-1]])

# viewing the first five rows of the data
df.head()

# Shape of dataframe
df.shape

# ssummary of the data
df.describe()

# Number of labels in the target column
df['target'].value_counts()

plt.figure(figsize=(20, 7))
df.groupby('target').size().plot(kind='pie', autopct='%.2f')
plt.title('Target label counts')

df['Attack Type'].value_counts()

plt.figure(figsize=(25, 7))
df.groupby('Attack Type').size().plot(kind='pie', autopct='%.2f')
plt.title('Attack type label counts')

# getting data type of each feature
df.dtypes

# Finding missing values of all features.
df.isnull().sum()

# Finding Categorical Features
num_cols = df._get_numeric_data().columns

cate_cols = list(set(df.columns) - set(num_cols))
cate_cols.remove('target')
cate_cols.remove('Attack Type')

cate_cols

# Exploratory data analysis
plt.figure(figsize=(10, 7))
class_distribution = df['Attack Type'].value_counts()
c = ['green', 'royalblue', 'grey', 'blue', 'orange']
class_distribution.plot(kind='bar', color=c)
plt.xlabel('Class')
plt.ylabel('Data points per Class')
plt.title('Distribution of Attack Type')
plt.show()


# Visualizing Categorical Features using bar graph
def bar_graph(feature):
    df[feature].value_counts().plot(kind="bar", color=c)


bar_graph('protocol_type')
plt.title("Distribution of protocol type")

plt.figure(figsize=(15, 3))
bar_graph('service')
plt.title("Distribution of service")

bar_graph('flag')
plt.title("Distribution of flag")

bar_graph('logged_in')

bar_graph('target')
plt.title("Distribution of target")

df.columns

df.hist(figsize=(20, 20))
plt.show()

# Data Correlation – Find the highly correlated variables
# using heatmap and ignore them for analysis.
df = df.dropna('columns')  # drop columns with NaN

df = df[[col for col in df if df[col].nunique() > 1]]  # keep columns where there are more than 1 unique values

corr = df.corr()

plt.figure(figsize=(30, 20))

sns.heatmap(corr, square=True, annot=True, fmt='.2f', linecolor='white')

plt.show()

# This variable is highly correlated with num_compromised and should be ignored for analysis.
# (Correlation = 0.9938277978738366)
df.drop('num_root', axis=1, inplace=True)

# This variable is highly correlated with serror_rate and should be ignored for analysis.
# (Correlation = 0.9983615072725952)
df.drop('srv_serror_rate', axis=1, inplace=True)

# This variable is highly correlated with rerror_rate and should be ignored for analysis.
# (Correlation = 0.9947309539817937)
df.drop('srv_rerror_rate', axis=1, inplace=True)

# This variable is highly correlated with srv_serror_rate and should be ignored for analysis.
# (Correlation = 0.9993041091850098)
df.drop('dst_host_srv_serror_rate', axis=1, inplace=True)

# This variable is highly correlated with rerror_rate and should be ignored for analysis.
# (Correlation = 0.9869947924956001)
df.drop('dst_host_serror_rate', axis=1, inplace=True)

# This variable is highly correlated with srv_rerror_rate and should be ignored for analysis.
# (Correlation = 0.9821663427308375)
df.drop('dst_host_rerror_rate', axis=1, inplace=True)

# This variable is highly correlated with rerror_rate and should be ignored for analysis.
# (Correlation = 0.9851995540751249)
df.drop('dst_host_srv_rerror_rate', axis=1, inplace=True)

# This variable is highly correlated with dst_host_srv_count and should be ignored for analysis.
# (Correlation = 0.9736854572953938)
df.drop('dst_host_same_srv_rate', axis=1, inplace=True)

# Remove irrelevant features such as ‘service’ before modelling
# Remove target as its the same as Attack Type
df.drop('service', axis=1, inplace=True)
df.drop('target', axis=1, inplace=True)

df.head()

df.shape

import seaborn as sns

sns.set(style="ticks", color_codes=True)
sns.pairplot(df, diag_kws={'color': 'red'}, plot_kws={'color': 'green'},
             vars=['Attack Type', 'duration', 'flag', 'protocol_type'])
plt.show()

df['protocol_type'].value_counts()

# protocol_type feature mapping
pmap = {'icmp': 0, 'tcp': 1, 'udp': 2}
df['protocol_type'] = df['protocol_type'].map(pmap)

df['flag'].value_counts()

# flag feature mapping
fmap = {'SF': 0, 'S0': 1, 'REJ': 2, 'RSTR': 3, 'RSTO': 4, 'SH': 5, 'S1': 6, 'S2': 7, 'RSTOS0': 8, 'S3': 9, 'OTH': 10}
df['flag'] = df['flag'].map(fmap)

df['Attack Type'].value_counts()

# attack_type feature mapping
amap = {'dos': 0, 'normal': 1, 'probe': 2, 'r2l': 3, 'u2r': 4}
df['Attack Type'] = df['Attack Type'].map(amap)

# Assigning the columns to X and Y
# Standardizing the X
from sklearn.preprocessing import StandardScaler

X = df.drop(['Attack Type', ], axis=1)
Y = df[['Attack Type']]
sc = StandardScaler()
X = sc.fit_transform(X)

print(X)

from sklearn.model_selection import train_test_split

# Split test and train data
X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.33, random_state=42)
print(X_train.shape, X_test.shape)
print(Y_train.shape, Y_test.shape)

from sklearn.cluster import KMeans

wcss = []
for i in range(1, 11):
    kmeans = KMeans(n_clusters=i, init='k-means++', random_state=42)
    kmeans.fit(X_train)
    wcss.append(kmeans.inertia_)
plt.plot(range(1, 11), wcss)
plt.title('The Elbow Method')
plt.xlabel('Number of clusters')
plt.ylabel('WCSS')
plt.show()

from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score
from sklearn.cluster import KMeans

range_n_clusters = [1, 2, 3, 4, 5, 6, 7]
Train_accuracy = []
for n in range_n_clusters:
    kmeans = KMeans(n_clusters=n, init='k-means++', random_state=42)
    kmeans.fit(X_train)

    print('Number of Clusters =', n, "Performance on train data")
    Y_pred_train = kmeans.predict(X_train)
    accuracy = accuracy_score(Y_train, Y_pred_train)
    print("Accuracy: ", accuracy)
    Train_accuracy.append(accuracy_score(Y_train, Y_pred_train))

plt.plot(range_n_clusters, Train_accuracy, color='green', linestyle='dashed', linewidth=3,
         marker='o', markerfacecolor='green', markersize=10)

# setting x and y axis range
plt.ylim(0, 1)
plt.xlim(1, 8)
# naming the x axis
plt.xlabel('Number of Clusters')
# naming the y axis
plt.ylabel('Accuracy Score')
plt.title('Optimal value of K w.r.t Accuracy')
plt.show()

# Training model on optimal value of K
kmeans = KMeans(n_clusters=3, init='k-means++', random_state=42)

kmeans.fit(X_train)
Y_predtrain = kmeans.predict(X_train)
ac = accuracy_score(Y_train, Y_predtrain)
print(ac)

# Making a prediction and getting the accuracy of the predicted labels
Y_predtest = kmeans.predict(X_test)
ac = accuracy_score(Y_test, Y_predtest)
print(ac)

# checking the labels given by KMeans model
kmeans.labels_

# Making a confusion matrix on K=3
cm = confusion_matrix(Y_test, Y_predtest)
print(cm)

# displaying a confusion Matrix on K=3
from sklearn import metrics

cm_display = metrics.ConfusionMatrixDisplay(confusion_matrix=cm)
cm_display.plot()
plt.show()

# importing classification report
from sklearn.metrics import classification_report

print(classification_report(Y_test, Y_predtest))

from sklearn.model_selection import cross_val_score

scores = cross_val_score(kmeans, X_train, Y_train, cv=5, scoring='accuracy')
print("cross-validation scores: {}".format(scores))
print("Average cross-validation score:{:.2f}".format(scores.mean()))

# Learning curve
from yellowbrick.model_selection import LearningCurve

sizes = np.linspace(0.3, 1.0, 10)
visualizer = LearningCurve(
    kmeans, cv=5, scoring='f1_weighted', train_sizes=sizes, n_jobs=4
)

visualizer.fit(X, Y)  # Fit the data to the visualizer
visualizer.show()

# PCA for feature selection
from sklearn.decomposition import PCA

pca = PCA()
x = pca.fit_transform(X_train)
pca.explained_variance_ratio_

# Selecting attributes with variance higher than 45%
x = df[['duration', 'protocol_type', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent']]
y = df[['Attack Type']]

# checking the shape od independent variable x
x.shape

# Standardize and split it into train and test set
sc = StandardScaler()
x = sc.fit_transform(x)

# Split test and train data
x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.30, random_state=42)
print(x_train.shape, x_test.shape)
print(y_train.shape, y_test.shape)

# Find optimal number of K through the ELbow Method
from sklearn.cluster import KMeans

wcss = []
for i in range(1, 11):
    kmeans = KMeans(n_clusters=i, init='k-means++', random_state=0)
    kmeans.fit(x_train)
    wcss.append(kmeans.inertia_)
plt.plot(range(1, 11), wcss)
plt.title('The Elbow Method')
plt.xlabel('Number of clusters')
plt.ylabel('WCSS')
plt.show()

# Find accuracy of the model against different number of K
from sklearn.metrics import confusion_matrix
from sklearn import metrics
from sklearn.cluster import KMeans

range_n_clusters = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
Train_accuracy = []
for n in range_n_clusters:
    kmeans = KMeans(n_clusters=n, init='k-means++', random_state=42)
    kmeans.fit(x_train)

    print('Number of Clusters =', n, "Performance on train data")
    y_pred_train = kmeans.predict(x_train)
    accuracy = accuracy_score(y_train, y_pred_train)
    print("Accuracy: ", accuracy)
    Train_accuracy.append(accuracy_score(y_train, y_pred_train))

# Plot the accuracy score against the value of K
plt.plot(range_n_clusters, Train_accuracy, color='green', linestyle='dashed', linewidth=3,
         marker='o')

# setting x and y axis range
plt.ylim(0, 1)
plt.xlim(1, 8)
# naming the x axis
plt.xlabel('Number of Clusters')
# naming the y axis
plt.ylabel('Accuracy Score')
plt.show()

# Fit the model on ptimal value of K
from sklearn.cluster import KMeans
from sklearn.metrics import accuracy_score

kmeans = KMeans(n_clusters=3, init='k-means++', random_state=42)

kmeans.fit(x_train)
y_predtrain = kmeans.predict(x_train)
ac = accuracy_score(y_train, y_predtrain)
print(ac)

# Predict the result of the test set on the trained model
y_predtest = kmeans.predict(x_test)
ac = accuracy_score(y_test, y_predtest)
print(ac)

# Print the confusion matrix
from sklearn.metrics import confusion_matrix, accuracy_score

cm = confusion_matrix(y_train, y_predtrain)
print(cm)

# display the heatmap of confusion matrix
cm_display = metrics.ConfusionMatrixDisplay(confusion_matrix=cm)
cm_display.plot()
plt.show()

# Print the classification report to check performance of data
from sklearn.metrics import classification_report

print(classification_report(y_train, y_predtrain))