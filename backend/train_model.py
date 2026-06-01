import pandas as pd #loads and manipulates the csv files or dataframes
import numpy as np  #handles numbers and arrays for numerical/math operations
from sklearn.ensemble import RandomForestClassifier  #the ML algorithm i'm using for detection
from sklearn.model_selection import train_test_split   #splits data into training and testing portions
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report #tools to measure how well the model performs
from sklearn.preprocessing import LabelEncoder #converts text labels like "BENIGN" and "ATTACK" into numbers that the model can understand 
import pickle #saves the trained model to a file so it can be used later without retraining so flask can load it later
import os #interacts with the file system to save and load the model file 

#load datasets
print("[INFO] Loading dataset...")

monday = pd.read_csv("dataset/Monday-WorkingHours.pcap_ISCX.csv")
wednesday = pd.read_csv("dataset/Wednesday-workingHours.pcap_ISCX.csv")

df = pd.concat([monday, wednesday], ignore_index=True)#pd.concat merges the two dataframes into one big table, df means dataframes
print(f"[INFO] Total Records Loaded: {len(df)}")

#clean column names 
df.columns = df.columns.str.strip() #removes the extra spaces from the column names so they are easier to work with without the model failing trying to find the Label column

#check label column 
#prints how many rows of each types exist in the Label column, enables seing how many normal and attack records we have to work with, this is important for understanding if the dataset is balanced or if we have a lot more of one type than the other which can affect how well the model learns
print("[INFO] Label Distribution:")
print(df['Label'].value_counts())

#simplify labels to binary (normal/attack)
#the original dataset has more specific labels for different types of attacks, but for this project we are simplifying it to just two categories: NORMAL and ATTACK. This makes it easier for the model to learn and focus on distinguishing between benign and malicious traffic without getting confused by the specific attack types.nakes the model's job easier
df['Label'] = df['Label'].apply(lambda x: 'NORMAL' if x == 'BENIGN' else 'ATTACK')

#drop non-numeric and problematic columns
df = df.drop(columns=['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Timestamp'], errors='ignore') #these columns contain text or unique identifiers that don't help the model learn patterns of normal vs attack traffic, so we remove them to focus on the numeric features that are more relevant for detection


#handle missing/infinite values
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

#Encode Labels
le = LabelEncoder() #LabelEncoder converts the text labels into numbers, for example NORMAL might become 1 and ATTACK might become 0, this is necessary because the machine learning model can only work with numbers
df['Label'] = le.fit_transform(df['Label']) #fit_transform learns the mapping of text to numbers and applies it to the Label column, ATTACK=0, NORMAL=1


#split features and target
X = df.drop(columns=['Label']) #X is the features, all the columns except Label which is what we want to predict
y = df['Label'] #y is the target variable, the Label column which indicates if it's NORMAL or ATTACK

#split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42) #this splits the data into a training set (70%) that we will use to train the model and a testing set (30%) that we will use to evaluate how well the model performs on unseen data. random_state=42 ensures that the split is reproducible
print(f"[INFO] training samples: {len(X_train)} | Test samples:{len(X_test)}")

#train random forest (model)
print("[INFO] Training Random Forest Model...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)#n_estimators=100 means we are using 100 decision trees in the random forest, random_state=42 ensures reproducibility, n_jobs=-1 allows the model to use all available CPU cores for faster training
model.fit(X_train, y_train)
print("[INFO] Model Training completed.")

#evaluate model
print("[INFO] Evaluating model...")
y_pred = model.predict(X_test) #this uses the trained model to make predictions on the test set, which we will compare to the actual labels to see how well the model performs
print("\n[RESULTS]")
print(f"Accuracy : {accuracy_score(y_test, y_pred) * 100:.2f}%") #accuracy is the percentage of correct predictions out of all predictions made
print(f"Precision: {precision_score(y_test, y_pred) * 100:.2f}%") #precision is the percentage of true positive predictions out of all positive predictions made by the model, it tells how many of the predicted attacks were actually attacks
print(f"Recall   : {recall_score(y_test, y_pred) * 100:.2f}%") #recall is the percentage of true positive predictions out of all actual positive cases in the test set, it tells how many of the actual attacks were correctly identified by the model
print(f"F1 Score : {f1_score(y_test, y_pred) * 100:.2f}%") #F1 score is the harmonic mean of precision and recall, it provides a single metric that balances both precision and recall, especially useful when the dataset is imbalanced
print("\n[CLASSIFICATION REPORT]")
print(classification_report(y_test, y_pred, target_names=le.classes_)) #this provides a detailed report of precision, recall, F1 score, and support for each class (NORMAL and ATTACK) which helps us understand how well the model is performing for each category


# Save feature columns
import json
with open('model/feature_columns.json', 'w') as f:
    json.dump(list(X_train.columns), f)
print("[INFO] Feature columns saved")


#save model
os.makedirs("model", exist_ok=True) #this creates a directory called "model" if it doesn't already exist, where we will save the trained model file
with open("model/ids_model.pkl", "wb") as f: #this opens a file called "ids_model.pk1" in the "model" directory for writing in binary mode, which is where we will save the trained model
    pickle.dump(model, f) #this saves the trained model object to the file using pickle, so we can load it later without having to retrain it

with open("model/label_encoder.pkl", "wb") as f: #this opens another file called "label_encoder.pk1" in the "model" directory for writing in binary mode, where the label encoder object will be saved 
    pickle.dump(le, f) #this saves the label encoder object to the file using pickle, so it can loaded later to decode the predicted labels back to NORMAL and ATTACK when we use the model for inference in the flask app

print("\n[INFO] Model saved to model/ids_model.pkl and model/label_encoder.pkl") #this prints a message to the console indicating that the model and label encoder have been successfully saved to the specified files